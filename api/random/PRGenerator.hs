-- | This module implements the pseudo-random generator using the
-- /fast key erasure technique/
-- (<https://blog.cr.yp.to/20170723-random.html>) parameterised on the
-- signatures "Implementation" and "Entropy". This technique is the
-- underlying algorithm used in systems like OpenBSD in their
-- implementation of arc4random.
--
-- __WARNING:__ These details are only for developers and reviewers of
-- raaz the library. A casual user should not be looking into this
-- module this let alone tweaking the code here.
--

{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE RecordWildCards   #-}
-- {-# LANGUAGE NamedFieldPun    #-}

module PRGenerator
       ( -- * Pseudo-random generator
         -- $internals$
         RandomState, reseed, fillRandomBytes
         -- ** Information about the cryptographic generator.
       , entropySource, csprgName, csprgImpl, csprgDescription
       ) where

import Foreign.Ptr ( castPtr )
import Entropy
import Prelude

import Raaz.Core
import Raaz.Core.Memory

import Implementation
import Context

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
-- internal state into pseudo-random bytes. However, there are tricky
-- issues regarding forward security that will make such a simplistic
-- algorithm insecure. Besides, where do we get our truly random seed
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
-- [Sampling:] Pre-computing a few blocks using `randomBlocks` that
-- will later on be used to satisfy satisfy the requests for random
-- bytes.
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


-- | The csprg algorithm used for stretching the seed.
csprgName :: String
csprgName = primName

-- | The implementation name used.
csprgImpl :: String
csprgImpl = name

-- | A short description of the csprg.
csprgDescription :: String
csprgDescription = description

-- | Memory for storing the csprg state.
data RandomState = RandomState { randomCxt       :: Cxt RandomBufferSize
                               , randomGenBlocks :: MemoryCell (BlockCount Prim)
                               }


instance Memory RandomState where
  memoryAlloc     = RandomState <$> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . randomCxt

-- | Gives access into the internals of the associated cipher.
instance WriteAccessible RandomState where
  writeAccess          = writeAccess . cxtInternals . randomCxt
  afterWriteAdjustment = afterWriteAdjustment . cxtInternals . randomCxt

-------------------------------- The PRG operations ---------------------------------------------

-- | Generate a new sample, i.e. fill the context with psrg.
sample :: RandomState -> IO ()
sample rstate@RandomState{..} = do
  genBlocks <- extract randomGenBlocks
  if genBlocks >= reseedAfter then reseed rstate
    else generateRandom rstate

-- | Reseed the state from the system entropy pool. The CSPRG
-- interface automatically takes care of reseeding from the entropy
-- pool at regular intervals and the user almost never needs to use
-- this.
reseed :: RandomState -> IO ()
reseed rstate@RandomState{..} = do
  unsafeInitWithEntropy rstate
  initialise zeroBlocks randomGenBlocks
  generateRandom rstate


-- | Generate random bytes into the context in one go which will then
-- be slowly released to the outside world. We also keep track of how
-- much blocks is generated which will be used to check when to reseed
-- the generator from system entropy.
generateRandom :: RandomState -> IO ()
generateRandom rstate@RandomState{..} = do
  unsafeGenerateBlocks randomBlocks randomCxt
  modifyMem (mappend $ cxtBlockCount $ pure randomCxt) randomGenBlocks
  unsafeInitFromBuffer rstate

------------------------------ DANGEROUS ACCESS manipulation ------------------------

--
-- These are highly unsafe code do not export. All hell breaks loose
-- otherwise.
--

-- | Initialise the internals from the entropy source.
unsafeInitWithEntropy :: RandomState -> IO ()
unsafeInitWithEntropy = mapM_ initWithEntropy . writeAccess
  where initWithEntropy Access{..} = getEntropy accessSize accessPtr

-- | Initialise the internals from the already generated blocks. CSPRG
-- implementations should ensure that the context is large enough to
-- hold enough bytes so even after initialising the internals, there
-- is enough data left to give out for subsequent calls. Otherwise
-- each sampling will result in a infinite loop.
unsafeInitFromBuffer :: RandomState -> IO ()
unsafeInitFromBuffer rstate@RandomState{..} = mapM_ initFromBuffer $ writeAccess rstate
  where initFromBuffer Access{..}
          = unsafeWriteTo accessSize (destination accessPtr) randomCxt


-- | Zero blocks of the primitive
zeroBlocks :: BlockCount Prim
zeroBlocks = 0 `blocksOf` Proxy


unsafeRandomBytes :: BYTES Int
                  -> Dest (Ptr Word8)
                  -> RandomState -> IO ()
unsafeRandomBytes sz destPtr rstate@RandomState{..}
  = go sz destPtr
  where go n ptr
          | n <= 0 = return ()
          | otherwise = do trfed <- unsafeWriteTo n ptr randomCxt
                           let more    = n - trfed
                               nextPtr = (`movePtr` trfed) <$> ptr
                             in when (more > 0) $ sample rstate >> go more nextPtr

-- | Fill a buffer pointed by the given pointer with random bytes.
fillRandomBytes :: (LengthUnit l, Pointer ptr)
                => l
                -> Dest (ptr a)
                -> RandomState
                -> IO ()
fillRandomBytes l ptr = unsafeRandomBytes (inBytes l) wptr
  where wptr = fmap (castPtr . unsafeRawPtr) ptr

instance ByteSource RandomState where
  fillBytes n rstate ptr
    = unsafeRandomBytes n (destination (castPtr ptr)) rstate >> return (Remaining rstate)
