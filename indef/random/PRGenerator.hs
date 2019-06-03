-- | This module implements the pseudo-random generator using the
-- /fast key erasure technique/
-- (<https://blog.cr.yp.to/20170723-random.html>) parameterised on the
-- signatures "Implementation" and "Entropy". This technique is the
-- underlying algorithm used in systems like OpenBSD in their
-- implementation of arc4random.
--
-- __Note:__ These details are only for developers and reviewers and a
-- casual user is discouraged from looking into this or worse tweaking
-- stuff here.
--

{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds        #-}
module PRGenerator
       ( -- * Pseudo-random generator
         -- $internals$
         RandomState, reseed, fillRandomBytes
         -- ** Information about the cryptographic generator.
       , entropySource, csprgName, csprgDescription
       ) where

import Control.Monad.Reader
import Entropy
import Prelude

import Raaz.Core

import Implementation
import Utils

-- $internals$
--
-- Generating unpredictable stream of bytes is one task that has burnt
-- the fingers of a lot of programmers. Unfortunately, getting it
-- correct is something of a black art. We give the internal details
-- of the cryptographic pseudo-random generator used in raaz. Note
-- that none of the details here are accessible or tuneable by the
-- user. This is a deliberate design choice to insulate the user from
-- things that are pretty easy to mess up.
--
-- The pseudo-random generator is essentially a primitive that
-- supports the generation of multiple blocks of data once its
-- internals are set. The overall idea is to set the internals from a
-- truly random source and then use the primitive to expand the
-- internal state into pseudo-random bytes. However there are tricky
-- issues regarding forward security that will make such a simplistic
-- algorithm insecure. Besides where do we get our truly random seed
-- to begin the process?
--
-- We more or less follow the /fast key erasure technique/
-- (<https://blog.cr.yp.to/20170723-random.html>) which is used in the
-- arc4random implementation in OpenBSD.  The two main steps in the
-- generation of the required random bytes are the following:
--
-- [Seeding:] Setting the internal state of a primitive. We use the
-- `getEntropy` function for this purposes.
--
-- [Sampling:] Pre-computing a few random blocks using the
-- `randomBlocks` function of in an auxiliary buffer which in turn is
-- used to satisfy the requests for random bytes.
--
-- Instead of running the `randomBlocks` for every request, we
-- generate `RandomBufferSize` blocks of random blocks in an auxiliary
-- buffer and satisfy requests for random bytes from this buffer. To
-- ensure that the compromise of the PRG state does not compromise the
-- random data already generated and given out, we do the following.
--
-- 1. After generating `RandomBufferSize` blocks of data in the
--    auxiliary buffer, we immediately re-initialise the internals of
--    the primitive from the auxiliary buffer. This ensures that there
--    is no way to know which internal state was used to generate the
--    current contents in the auxiliary buffer.
--
-- 2. Every use of data from the auxiliary buffer, whether it is to
--    satisfy a request for random bytes or to reinitialise the
--    internals in step 1 is wiped out immediately.
--
-- Assuming the security of the entropy source given by the
-- `getEntropy` and the random block generator given by the
-- `randomBlocks` we have the following security guarantee.
--
-- [Security Guarantee:] At any point of time, a compromise of the
-- cipher state (i.e. key iv pair) and/or the auxiliary buffer does
-- not reveal the random data that is given out previously.
--


-- | Name of the csprg used for stretching the seed.
csprgName :: String
csprgName = name

-- | A short description of the csprg.
csprgDescription :: String
csprgDescription = description

-- | The buffer to store randomness.
type RandomBuffer = Buffer RandomBufferSize

-- | Memory for storing the csprg state.
data RandomState = RandomState { internals       :: Internals
                               , auxBuffer       :: RandomBuffer
                               , remainingBytes  :: MemoryCell (BYTES Int)
                               , blocksGenerated :: MemoryCell (BLOCKS Prim)
                               }


instance Memory RandomState where
  memoryAlloc     = RandomState <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer  . internals

-------------------------------- The PRG operations ---------------------------------------------

-- | This function generates new random bytes just like
-- `newSample`. However, it fills the state with entropy form the
-- system if required.
sampleWithSeedIfReq :: MT RandomState ()
sampleWithSeedIfReq = do
  nGenBlocks <- getGenBlocks
  if nGenBlocks >= reseedAfter
    then clearBlocks >> reseed
    else newSample
  where getGenBlocks = withReaderT blocksGenerated extract
        clearBlocks = withReaderT blocksGenerated $ initialise (blocksOf 0 (Proxy :: Proxy Prim))

-- | Reseed the prg from the system entropy pool.
reseed :: MT RandomState ()
reseed = runOnInternals initFromEntropyPool >> newSample
  where initFromEntropyPool = withMemoryPtr getEntropy

-- | This fills in the auxiliary buffer with some generated bytes. A
-- portion of this generated bytes is used to re-initialise the
-- Internal memory with key that an accidental revelation of the state
-- will not compromise the past bytes that are generated.
newSample :: MT RandomState ()
newSample = generateRandom >> reInitStateFromBuffer

-- | Generate random bytes into the buffer in one go which will then
-- be slowly released to the outside world. We need to do some book
-- keeping here namely, updating the total bytes remaining and the
-- total number of blocks of the primitive generated.
generateRandom :: MT RandomState ()
generateRandom = withAuxBuffer csprgBuf
                 >> updateGenBlocks
                 >> setRemainingBytes howMuch
  where csprgBuf bufPtr = withReaderT internals $ randomBlocks bufPtr howMuch
        updateGenBlocks = withReaderT blocksGenerated $ modify (mappend howMuch)
        howMuch         = bufferSize (Proxy :: Proxy RandomBuffer)


-- | Re-initialise the internal state from the auxiliary buffer.
reInitStateFromBuffer :: MT RandomState ()
reInitStateFromBuffer = do
  rdr <- initialiser <$> runOnInternals ask
  let nbytes = transferSize rdr
    in unsafeWithExisting nbytes (runOnInternals . unsafeTransfer rdr)

-------------------------- Some helper functions on random state -------------------

-- | Run an action on the auxilary buffer.
withAuxBuffer :: (BufferPtr -> MT RandomState a) -> MT RandomState a
withAuxBuffer action = askBufferPointer >>= action
  where askBufferPointer = asks $ getBufferPointer . auxBuffer

runOnInternals :: MT Internals a -> MT RandomState a
runOnInternals = withReaderT internals

-- | Get the number of bytes in the buffer.
getRemainingBytes :: MT RandomState (BYTES Int)
getRemainingBytes = withReaderT remainingBytes extract

-- | Set the number of remaining bytes.
setRemainingBytes :: LengthUnit l => l -> MT RandomState ()
setRemainingBytes = withReaderT remainingBytes . initialise . inBytes



--------------------------- DANGEROUS CODE ---------------------------------------

-- NONTRIVIALITY: Picking up the newSample is important when we first
-- reseed.

-- | The function to generate random bytes. Fills from existing bytes
-- and continues if not enough bytes are obtained.
fillRandomBytes :: LengthUnit l => l -> Pointer -> MT RandomState ()
fillRandomBytes l = go (inBytes l)
  where go m ptr
          | m > 0     = do mGot <- fillExistingBytes m ptr   -- Fill from the already generated buffer.
                           when (mGot <= 0) sampleWithSeedIfReq
                           go (m - mGot) $ movePtr ptr mGot  -- Get the remaining.
          | otherwise = return ()   -- Nothing to do


-- | Fill from already existing bytes. Returns the number of bytes
-- filled. Let remaining bytes be r. Then fillExistingBytes will fill
-- min(r,m) bytes into the buffer, and return the number of bytes
-- filled.
fillExistingBytes :: BYTES Int -> Pointer -> MT RandomState (BYTES Int)
fillExistingBytes req ptr = do
  r <- getRemainingBytes
  let m = min r req
    in do unsafeWithExisting m (\ sPtr -> memcpy (destination ptr) (source sPtr) m)
          return m

-- | Transfer from existing bytes. This is unsafe because no checks is
-- done to see if there are enough bytes to transfer.
unsafeWithExisting :: BYTES Int
                   -> (Pointer -> MT RandomState ())
                   -> MT RandomState ()
unsafeWithExisting m action =  withAuxBuffer $ \ buf -> do
  r <- getRemainingBytes
  let sptr    = forgetAlignment buf --
      l       = r - m               -- leftovers
      tailPtr = movePtr sptr l
      in do
    -- Fills the source ptr from the end.
    --  sptr                tailPtr
    --   |                  |
    --   V                  V
    --   -----------------------------------------------------
    --   |   l              |    m                           |
    --   -----------------------------------------------------
    action tailPtr          -- run the transfer action from the tail.
    wipeMemory tailPtr m    -- wipe the bytes already transfered.
    setRemainingBytes l     -- set leftover bytes.
