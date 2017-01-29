-- | This sets up the recommended implementation of chacha20 cipher.

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE CPP                  #-}

--
-- The orphan instance declaration separates the implementation and
-- setting the recommended instances. Therefore, we ignore the warning.
--

module Raaz.Cipher.ChaCha20.Recommendation
       ( chacha20Block, RandomBuf, getBufferPointer, randomBufferSize
       ) where

import Control.Applicative
import Prelude

import Raaz.Core
import Raaz.Cipher.ChaCha20.Internal

#ifdef HAVE_VECTOR_256
import Raaz.Cipher.ChaCha20.Implementation.Vector256
#else
import Raaz.Cipher.ChaCha20.Implementation.CPortable
#endif


--------------- Some information used by Raaz/Random/ChaCha20PRG.hs -------------

-- | The chacha stream cipher is also used as the prg for generating
-- random bytes. Such a prg needs to keep an auxilary buffer type so
-- that one can generate random bytes not just of block size but
-- smaller. This memory type is essentially for maintaining such a
-- buffer.

newtype RandomBuf = RandomBuf { unBuf :: Pointer }


-- | The size of the buffer in blocks of ChaCha20. While the
-- implementations should handly any multiple of blocks, often
-- implementations naturally handle some multiple of blocks, for
-- example the Vector256 implementation handles 2-chacha blocks. Set
-- this quantity to the maximum supported by all implementations.
randomBufferSize :: BLOCKS ChaCha20
randomBufferSize = 2  `blocksOf` ChaCha20


-- | Implementations are also designed to work with a specific
-- alignment boundary. Unaligned access can slow down the primitives
-- quite a bit. Set this to the maximum of alignment supported by all
-- implementations
randomBufferAlignment :: Alignment
randomBufferAlignment = 32 -- For 256-bit vector instructions.


instance Memory RandomBuf where

  memoryAlloc     = RandomBuf <$> pointerAlloc sz
    where sz = atLeastAligned randomBufferSize randomBufferAlignment

  unsafeToPointer = unBuf

-- | Get the actual location where the data is to be stored. Ensures
-- that the pointer is aligned to the @randomBufferAlignment@
-- restriction.
getBufferPointer :: MT RandomBuf Pointer
getBufferPointer = actualPtr <$> getMemory
  where actualPtr = flip alignPtr randomBufferAlignment . unBuf


------------ Setting the recommended implementation -------------------

instance Recommendation ChaCha20 where
         recommended _ = implementation
