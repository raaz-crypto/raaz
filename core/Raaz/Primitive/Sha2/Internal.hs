{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

-- |
--
-- Module      : Raaz.Primitive.Sha2.Internal
-- Description : Internal modules for sha2 family of hashes.
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
module Raaz.Primitive.Sha2.Internal
       ( -- * The sha2 types
         Sha512, Sha256
       , Sha512Mem, Sha256Mem
       , process512Last
       , process256Last
       ) where

import           Data.Vector.Unboxed        ( Unbox )
import           Foreign.Storable           ( Storable(..) )
import           GHC.TypeLits


import           Raaz.Core
import           Raaz.Core.Transfer.Unsafe
import           Raaz.Primitive.HashMemory

----------------------------- The blake2 type ---------------------------------

-- | The Sha2 type.
newtype Sha2 w = Sha2 (Tuple 8 w)
               deriving (Eq, Equality, Storable, EndianStore)

instance ( Unbox w
         , EndianStore w
         ) => Primitive (Sha2 w) where
  type WordType      (Sha2 w) = w
  type WordsPerBlock (Sha2 w) = 16


instance (Unbox w, EndianStore w) => Encodable (Sha2 w)

instance (EndianStore w, Unbox w) => IsString (Sha2 w) where
  fromString = fromBase16

instance (EndianStore w, Unbox w) => Show (Sha2 w) where
  show =  showBase16


-- | The Sha512 cryptographic hash.
type Sha512 = Sha2 (BE Word64)

-- | The Sha256 cryptographic hash.
type Sha256 = Sha2 (BE Word32)

-- | The initial value to start the blake2b hashing. This is equal to
-- the iv `xor` the parameter block.
sha512Init :: Sha512
sha512Init = Sha2 $ unsafeFromList [ 0x6a09e667f3bcc908
                                   , 0xbb67ae8584caa73b
                                   , 0x3c6ef372fe94f82b
                                   , 0xa54ff53a5f1d36f1
                                   , 0x510e527fade682d1
                                   , 0x9b05688c2b3e6c1f
                                   , 0x1f83d9abfb41bd6b
                                   , 0x5be0cd19137e2179
                                   ]

-- | The initial value to start the blake2b hashing. This is equal to
-- the iv `xor` the parameter block.
sha256Init :: Sha256
sha256Init = Sha2 $ unsafeFromList [ 0x6a09e667
                                   , 0xbb67ae85
                                   , 0x3c6ef372
                                   , 0xa54ff53a
                                   , 0x510e527f
                                   , 0x9b05688c
                                   , 0x1f83d9ab
                                   , 0x5be0cd19
                                   ]

---------------------------------- Memory element for Sha512 -----------------------

-- | The memory used by sha512 implementations.
type Sha512Mem = HashMemory128 Sha512

-- | The memory used bha sha256 implementations.
type Sha256Mem = HashMemory64 Sha256

instance Initialisable Sha256Mem () where
  initialise _ = initialise sha256Init

instance Initialisable Sha512Mem () where
  initialise _ = initialise sha512Init


-- | The block compressor for sha256.
type Compressor256 n =  AlignedBlockPtr n Sha256
                     -> BlockCount Sha256
                     -> Sha256Mem -> IO ()
-- | The block compressor for sha512
type Compressor512 n =  AlignedBlockPtr n Sha512
                     -> BlockCount Sha512
                     -> Sha512Mem -> IO ()

-- | Takes a block processing function for sha256 and gives a last
-- bytes processor.
process256Last :: KnownNat n
               => Compressor256 n    -- ^ block compressor
               -> AlignedBlockPtr n Sha256
               -> BYTES Int
               -> Sha256Mem
               -> IO ()
process256Last comp buf nbytes sha256mem = do
  updateLength nbytes sha256mem
  totalBytes  <- fmap bigEndian <$> getLength sha256mem
  let pad      = padding256 nbytes totalBytes
      blocks   = atMost $ transferSize pad
    in unsafeTransfer pad buf >> comp buf blocks sha256mem

-- | Takes a block processing function for sha512 and gives a last
-- bytes processor.
process512Last :: KnownNat n
               => Compressor512 n
               -> AlignedBlockPtr n Sha512
               -> BYTES Int
               -> Sha512Mem
               -> IO ()
process512Last comp buf nbytes sha512mem = do
  updateLength128 nbytes sha512mem
  uLen  <- fmap bigEndian <$> getULength sha512mem
  lLen  <- fmap bigEndian <$> getLLength sha512mem
  let pad      = padding512 nbytes uLen lLen
      blocks   = atMost $ transferSize pad
      in unsafeTransfer pad buf >> comp buf blocks sha512mem

-- | The padding for sha256 as a writer.
padding256 :: BYTES Int         -- Data in buffer.
           -> BYTES (BE Word64) -- Message length
           -> WriteTo
padding256 bufSize msgLen  =
  glueWrites 0 boundary (padBit1 bufSize) lengthWrite
  where boundary    = blocksOf 1 (Proxy :: Proxy Sha256)
        lengthWrite = write $ shiftL msgLen 3

-- | The padding for sha512 as a writer.
padding512 :: BYTES Int         -- Data in buffer.
           -> BYTES (BE Word64) -- Message length higher
           -> BYTES (BE Word64) -- Message length lower
           -> WriteTo
padding512 bufSize uLen lLen  = glueWrites 0 boundary (padBit1 bufSize) lengthWrite
  where boundary    = blocksOf 1 (Proxy :: Proxy Sha512)
        lengthWrite = write up `mappend` write lp
        up          = shiftL uLen 3 .|. shiftR lLen 61
        lp          = shiftL lLen 3


-- | Pad the message with a 1-bit.
padBit1 :: BYTES Int -- ^ message length
        -> WriteTo
padBit1  sz = skip sz <> writeStorable (0x80 :: Word8)
