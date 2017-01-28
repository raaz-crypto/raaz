-- | The module exposes the ChaCha20 based PRG.
{-# LANGUAGE FlexibleContexts #-}
module Raaz.Random.ChaCha20PRG
       ( reseedMT, fillRandomBytesMT, RandomState(..)
       ) where

import Control.Monad
import Foreign.Ptr   (Ptr, castPtr)
import Raaz.Core
import Raaz.Cipher.ChaCha20.Internal
import Raaz.Cipher.ChaCha20.Recommendation
import Raaz.Entropy

-- | The maximum value of counter before reseeding from entropy
-- source. Currently set to 1024 * 1024 * 1024. Which will generate
-- 64GB before reseeding.
maxCounterVal :: Counter
maxCounterVal = 1024 * 1024 * 1024


-- | Memory for strong the internal memory state.
data RandomState = RandomState { chacha20State  :: ChaCha20Mem
                               , auxBuffer      :: MemoryCell RandomBlock
                               , remainingBytes :: MemoryCell (BYTES Int)
                               }

-------------------------- Some helper functions on random state -------------------

-- | Run an action on the auxilary buffer.
withAuxBuffer :: (Ptr something -> MT RandomState a) -> MT RandomState a
withAuxBuffer action = onSubMemory auxBuffer getCellPointer >>= action . castPtr

-- | Get the number of bytes in the buffer.
getRemainingBytes :: MT RandomState (BYTES Int)
getRemainingBytes = onSubMemory remainingBytes extract

-- | Set the number of remaining bytes.
setRemainingBytes :: BYTES Int -> MT RandomState ()
setRemainingBytes = onSubMemory remainingBytes . initialise

instance Memory RandomState where
  memoryAlloc     = RandomState <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer  . chacha20State



-- | This fills in the random block with some new randomness
newSample :: MT RandomState ()
newSample = do setRemainingBytes sampleSize
               onSubMemory chacha20State seedIfReq
               withAuxBuffer     $ onSubMemory chacha20State . chacha20Random
  where sampleSize = sizeOf (undefined :: RandomBlock)

-- | See the PRG from system entropy.
seed :: MT ChaCha20Mem ()
seed = do onSubMemory counterCell $ initialise (0 :: Counter)
          onSubMemory keyCell getCellPointer >>= void . getEntropy keySize . castPtr
          onSubMemory ivCell  getCellPointer >>= void . getEntropy ivSize  . castPtr
  where keySize = sizeOf (undefined :: KEY)
        ivSize  = sizeOf (undefined :: IV)

-- | Seed if we have already generated maxCounterVal blocks of random
-- bytes.
seedIfReq :: MT ChaCha20Mem ()
seedIfReq = do c <- onSubMemory counterCell extract
               when (c > maxCounterVal) $ seed


--------------------------- DANGEROUS CODE ---------------------------------------



-- remaining bytes, this can produce a lot of nonsense.

-- | Reseed the prg.
reseedMT :: MT RandomState ()
reseedMT = onSubMemory chacha20State seed >> newSample

-- NONTRIVIALITY: Picking up the newSample is important when we first
-- reseed.

-- | The function to generate random bytes. Fills from existing bytes
-- and continues if not enough bytes are obtained.
fillRandomBytesMT :: LengthUnit l => l -> Pointer -> MT RandomState ()
fillRandomBytesMT l = go (inBytes l)
  where go m ptr
          | m  <= 0    = return ()   -- Nothing to do
          | otherwise  = do
              mGot <- fillExistingBytes m ptr   -- Fill some
              go
                (m - mGot)          -- bytes yet to get.
                $ movePtr ptr mGot  -- Shift by what is already got.


-- | Fill from already existing bytes. Returns the number of bytes
-- filled. Let remaining bytes be r. Then fillExistingBytes will fill
-- min(r,m) bytes into the buffer, and return the number of bytes
-- filled.
fillExistingBytes :: BYTES Int -> Pointer -> MT RandomState (BYTES Int)
fillExistingBytes m ptr = do
  r <- getRemainingBytes
  withAuxBuffer $ \ sptr -> do
    if r <= m then do memcpy (destination ptr) (source sptr) r -- read the entire stuff.
                      newSample
                      return r
      else let leftOver = r - m                 -- Bytes leftover
               tailPtr  = movePtr sptr leftOver -- We read the last m bytes.
           in do memcpy (destination ptr) (source tailPtr) m
                 setRemainingBytes leftOver
                 return m


-- The function fillExisting bytes reads from the end. See the picture
-- below
--
--
--    ---------------------------------------------------------------------
--    |   (r - m) remaining bytes        |     m bytes consumed           |
--    ---------------------------------------------------------------------
--
