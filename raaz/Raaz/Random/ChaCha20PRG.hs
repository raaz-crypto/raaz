-- | The module exposes the ChaCha20 based PRG.
{-# LANGUAGE FlexibleContexts #-}
module Raaz.Random.ChaCha20PRG
       ( reseedMT, fillRandomBytesMT, RandomState
       ) where

import Control.Applicative
import Control.Monad
import Control.Monad.Reader   ( ask, withReaderT )
import Data.Monoid
import Data.Proxy             ( Proxy(..)        )
import Foreign.Ptr            ( castPtr          )
import Prelude

import Raaz.Core
import Raaz.Primitive.ChaCha20.Internal
import Raaz.Cipher.ChaCha20.Util as U
import Raaz.Entropy


-- | The maximum value of counter before reseeding from entropy
-- source. Currently set to 1024 * 1024 * 1024. Which will generate
-- 64GB before reseeding.
--
-- The reason behind the choice of the reseeding limit is the
-- following The counter is a 32-bit quantity. Which means that one
-- can generate 2^32 blocks of data before the counter roles over and
-- starts repeating. We have choosen a conservative 2^30 blocks
-- here. Note that the roll over of the counter is not really relevant
-- here as we updated the key,iv for every few chunks of the chacha20
-- key stream (note the fast key erasure technique
-- <https://blog.cr.yp.to/20170723-random.html>) but still this gives
-- some justification for the choice of the parameter.
maxCounterVal :: Counter
maxCounterVal = 1024 * 1024 * 1024

-- | Memory for strong the internal memory state.
data RandomState = RandomState { chacha20State  :: U.Internals
                               , auxBuffer      :: RandomBuf
                               , remainingBytes :: MemoryCell (BYTES Int)
                               }


instance Memory RandomState where
  memoryAlloc     = RandomState <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer  . chacha20State

-------------------------- Some helper functions on random state -------------------

-- | Run an action on the auxilary buffer.
withAuxBuffer :: (BufferPtr -> MT RandomState a) -> MT RandomState a
withAuxBuffer action = withReaderT auxBuffer getBufferPointer >>= action

-- | Get the number of bytes in the buffer.
getRemainingBytes :: MT RandomState (BYTES Int)
getRemainingBytes = withReaderT remainingBytes extract

-- | Set the number of remaining bytes.
setRemainingBytes :: BYTES Int -> MT RandomState ()
setRemainingBytes = withReaderT remainingBytes . initialise

-------------------------------- The PRG operations ---------------------------------------------

-- | The overall idea is to generate a key stream into the auxilary
-- buffer using chacha20 and giving out bytes from this buffer. This
-- operation we call sampling. A portion of the sample is used for
-- resetting the key and iv to make the prg safe against backward
-- prediction, i.e. even if one knows the current seed (i.e. key iv
-- pair) one cannot predict the random values generated before.



-- | This fills in the random block with some new randomness
newSample :: MT RandomState ()
newSample = do
  seedIfReq
  --
  -- Generate key stream
  --
  withAuxBuffer $ withReaderT chacha20State . chacha20Random
  setRemainingBytes $ inBytes randomBufferSize
  --
  -- Use part of the generated data to re-key the chacha20 cipher
  --
  fillKeyIVWith fillExistingBytes


-- | See the PRG from system entropy.
seed :: MT RandomState ()
seed = do withReaderT (counterCell . chacha20State) $ initialise (0 :: Counter)
          fillKeyIVWith getEntropy

-- | Seed if we have already generated maxCounterVal blocks of random
-- bytes.
seedIfReq :: MT RandomState ()
seedIfReq = do c <- withReaderT (counterCell . chacha20State) extract
               when (c > maxCounterVal) seed

-- | Fill the iv and key from a filling function.
fillKeyIVWith :: (BYTES Int -> Pointer -> MT RandomState a) -- ^ The function used to fill the buffer
              -> MT RandomState ()
fillKeyIVWith filler = let
  keySize = sizeOf (Proxy :: Proxy KEY)
  ivSize  = sizeOf (Proxy :: Proxy IV)
  in do withReaderT (keyCell . chacha20State) getCellPointer >>= void . filler keySize . castPtr
        withReaderT (ivCell  . chacha20State) getCellPointer >>= void . filler ivSize  . castPtr





--------------------------- DANGEROUS CODE ---------------------------------------

-- | Reseed the prg.
reseedMT :: MT RandomState ()
reseedMT = seed >> newSample

-- NONTRIVIALITY: Picking up the newSample is important when we first
-- reseed.

-- | The function to generate random bytes. Fills from existing bytes
-- and continues if not enough bytes are obtained.
fillRandomBytesMT :: LengthUnit l => l -> Pointer -> MT RandomState ()
fillRandomBytesMT l = go (inBytes l)
  where go m ptr
            | m > 0  = do mGot <- fillExistingBytes m ptr   -- Fill from the already generated buffer.
                          when (mGot <= 0) newSample        -- We did not get any so sample.
                          go (m - mGot) $ movePtr ptr mGot  -- Get the remaining.
            | otherwise = return ()   -- Nothing to do


-- | Fill from already existing bytes. Returns the number of bytes
-- filled. Let remaining bytes be r. Then fillExistingBytes will fill
-- min(r,m) bytes into the buffer, and return the number of bytes
-- filled.
fillExistingBytes :: BYTES Int -> Pointer -> MT RandomState (BYTES Int)
fillExistingBytes req ptr = withAuxBuffer $ \ buf -> do
  let sptr = forgetAlignment buf
      in do r <- getRemainingBytes
            let m  = min r req            -- actual bytes filled.
                l  = r - m                -- leftover
                tailPtr = movePtr sptr l
              in do
              -- Fills the source ptr from the end.
              --  sptr                tailPtr
              --   |                  |
              --   V                  V
              --   -----------------------------------------------------
              --   |   l              |    m                           |
              --   -----------------------------------------------------
              memcpy (destination ptr) (source tailPtr) m -- transfer the bytes to destination
              memset tailPtr 0 m                          -- wipe the bytes already transfered.
              setRemainingBytes l                         -- set leftover bytes.
              return m


---------------------- The auxilary buffer ----------------------------

-- | The chacha stream cipher is also used as the prg for generating
-- random bytes. Such a prg needs to keep an auxilary buffer type so
-- that one can generate random bytes not just of block size but
-- smaller. This memory type is essentially for maintaining such a
-- buffer.

newtype RandomBuf = RandomBuf { unBuf :: Pointer }

--------------------- DANGEROUS CODE --------------------------------

-- | The size of the buffer in blocks of ChaCha20. While the
-- implementations should handle any multiple of blocks, often
-- implementations naturally handle some multiple of blocks, for
-- example the Vector256 implementation handles 2-chacha blocks. Set
-- this quantity to the maximum supported by all implementations.
randomBufferSize :: BLOCKS ChaCha20
randomBufferSize = 16  `blocksOf` (Proxy :: Proxy ChaCha20)

-- | Implementations are also designed to work with a specific
-- alignment boundary. Unaligned access can slow down the primitives
-- quite a bit.
randomBufferAlignment :: Alignment
randomBufferAlignment = ptrAlignment (Proxy :: Proxy U.BufferPtr)

instance Memory RandomBuf where
  memoryAlloc = RandomBuf <$> pointerAlloc sz
    where sz = atLeastAligned actualSize randomBufferAlignment
          actualSize = randomBufferSize <> U.additionalBlocks
  unsafeToPointer = unBuf

-- | Get the actual location where the data is to be stored. Ensures
-- that the pointer is aligned to the @randomBufferAlignment@
-- restriction.
getBufferPointer :: MT RandomBuf BufferPtr
getBufferPointer = actualPtr <$> ask
  where actualPtr = nextAlignedPtr . unBuf

-- | Use the chacha20 encryption algorithm as a prg.
chacha20Random :: BufferPtr -> MT U.Internals ()
chacha20Random = flip U.processBlocks randomBufferSize
