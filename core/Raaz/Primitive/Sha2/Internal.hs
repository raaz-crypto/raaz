{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

-- | Internal types and function for sha2 hashes.
module Raaz.Primitive.Sha2.Internal
       ( -- * The sha2 types
         SHA512, SHA256
       , Sha512Mem, Sha256Mem
       , process512Last
       , process256Last
       ) where

import           Data.Bits
import           Data.Proxy
import           Data.String
import           Data.Word
import           Foreign.Storable           ( Storable(..) )
import           Prelude      hiding        ( zipWith      )

import           Raaz.Core
import           Raaz.Core.Types.Internal
import           Raaz.Primitive.HashMemory

----------------------------- The blake2 type ---------------------------------

-- | The SHA2 type.
newtype SHA2 w = SHA2 (Tuple 8 w)
               deriving (Eq, Equality, Storable, EndianStore)

-- | The Sha512 cryptographic hash.
type SHA512 = SHA2 (BE Word64)

-- | The Sha256 cryptographic hash.
type SHA256 = SHA2 (BE Word32)

instance Encodable SHA512
instance Encodable SHA256


instance IsString SHA512 where
  fromString = fromBase16

instance IsString SHA256 where
  fromString = fromBase16

instance Show SHA512 where
  show =  showBase16

instance Show SHA256 where
  show =  showBase16

instance Primitive SHA512 where
  type BlockSize SHA512      = 128

instance Primitive SHA256 where
  type BlockSize SHA256      = 64

-- | The initial value to start the blake2b hashing. This is equal to
-- the iv `xor` the parameter block.
sha512Init :: SHA512
sha512Init = SHA2 $ unsafeFromList [ 0x6a09e667f3bcc908
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
sha256Init :: SHA256
sha256Init = SHA2 $ unsafeFromList [ 0x6a09e667
                                   , 0xbb67ae85
                                   , 0x3c6ef372
                                   , 0xa54ff53a
                                   , 0x510e527f
                                   , 0x9b05688c
                                   , 0x1f83d9ab
                                   , 0x5be0cd19
                                   ]

---------------------------------- Memory element for SHA512 -----------------------

type Sha512Mem = HashMemory128 SHA512
type Sha256Mem = HashMemory64 SHA256

instance Initialisable Sha256Mem () where
  initialise _ = initialise sha256Init

instance Initialisable Sha512Mem () where
  initialise _ = initialise sha512Init


-- | The block compressor for sha256.
type Compressor256 n =  AlignedPointer n
                     -> BLOCKS SHA256
                     -> MT Sha256Mem ()
-- | The block compressor for sha512
type Compressor512 n =  AlignedPointer n
                     -> BLOCKS SHA512
                     -> MT Sha512Mem ()

-- | Takes a block processing function for sha256 and gives a last
-- bytes processor.
process256Last :: Compressor256 n    -- ^ block compressor
               -> AlignedPointer n
               -> BYTES Int
               -> MT Sha256Mem ()
process256Last comp buf nbytes  = do
  updateLength nbytes
  totalBytes  <- getLength
  let pad      = padding256 nbytes totalBytes
      blocks   = atMost $ transferSize pad
    in unsafeTransfer pad (forgetAlignment buf) >> comp buf blocks

-- | Takes a block processing function for sha512 and gives a last
-- bytes processor.
process512Last :: Compressor512 n
               -> AlignedPointer n
               -> BYTES Int
               -> MT Sha512Mem ()
process512Last comp buf nbytes  = do
  updateLength128 nbytes
  uLen  <- getULength
  lLen  <- getLLength
  let pad      = padding512 nbytes uLen lLen
      blocks   = atMost $ transferSize pad
      in unsafeTransfer pad (forgetAlignment buf) >> comp buf blocks

-- | The padding for sha256 as a writer.
padding256 :: BYTES Int    -- Data in buffer.
           -> BYTES Word64 -- Message length
           -> WriteM (MT Sha256Mem)
padding256 bufSize msgLen  =
  glueWrites 0 boundary hdr lengthWrite
  where skipMessage = skip bufSize
        oneBit      = writeStorable (0x80 :: Word8)
        hdr         = skipMessage `mappend` oneBit
        boundary    = blocksOf 1 (Proxy :: Proxy SHA256)
        lengthWrite = write $ bigEndian (shiftL w 3)
        BYTES w     = msgLen

-- | The padding for sha512 as a writer.
padding512 :: BYTES Int    -- Data in buffer.
           -> BYTES Word64 -- Message length higher
           -> BYTES Word64 -- Message length lower
           -> WriteM (MT Sha512Mem)
padding512 bufSize uLen lLen  = glueWrites 0 boundary hdr lengthWrite
  where skipMessage = skip bufSize
        oneBit      = writeStorable (0x80 :: Word8)
        hdr         = skipMessage `mappend` oneBit
        boundary    = blocksOf 1 (Proxy :: Proxy SHA512)
        lengthWrite = write (bigEndian up) `mappend` write (bigEndian lp)
        BYTES up    = shiftL uLen 3 .|. shiftR lLen 61
        BYTES lp    = shiftL lLen 3
