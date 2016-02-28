{-# LANGUAGE CPP                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

module Raaz.Hash.Sha512.Internal ( SHA512(..), cPortable ) where


import           Data.String
import           Data.Word
import           Foreign.Storable    ( Storable(..) )

import           Raaz.Core
import           Raaz.Hash.Sha.Util

import           Raaz.Hash.Internal

----------------------------- SHA512 ---------------------------------

-- | The Sha512 hash value. Used in implementation of Sha384 as well.
newtype SHA512 = SHA512 (Tuple 8 (BE Word64))
               deriving (Eq, Equality, Storable, EndianStore)

instance Encodable SHA512

instance IsString SHA512 where
  fromString = fromBase16

instance Show SHA512 where
  show =  showBase16

instance Primitive SHA512 where
  blockSize _ = BYTES 128
  type Implementation SHA512 = SomeHashI SHA512
  recommended  _             = SomeHashI cPortable

instance Initialisable (HashMemory SHA512) () where
  initialise _ = initialise $ SHA512
                 $ unsafeFromList [ 0x6a09e667f3bcc908
                                  , 0xbb67ae8584caa73b
                                  , 0x3c6ef372fe94f82b
                                  , 0xa54ff53a5f1d36f1
                                  , 0x510e527fade682d1
                                  , 0x9b05688c2b3e6c1f
                                  , 0x1f83d9abfb41bd6b
                                  , 0x5be0cd19137e2179
                                  ]

instance Hash SHA512 where
  additionalPadBlocks _ = 1

------------------- The portable C implementation ------------

cPortable :: HashI SHA512 (HashMemory SHA512)
cPortable = shaImplementation c_sha512_compress length128Write

foreign import ccall unsafe
  "raaz/hash/sha512/portable.h raazHashSha512PortableCompress"
  c_sha512_compress  :: Pointer -> Int -> Pointer -> IO ()
