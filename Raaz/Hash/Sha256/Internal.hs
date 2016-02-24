{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

module Raaz.Hash.Sha256.Internal ( SHA256(..), cPortable ) where

import           Control.Applicative ( (<$>) )
import           Data.String
import qualified Data.Vector.Unboxed                  as VU
import           Data.Word
import           Data.Typeable       ( Typeable     )
import           Foreign.Ptr         ( castPtr      )
import           Foreign.Storable    ( Storable(..) )

import           Raaz.Core
import           Raaz.Core.Parse.Applicative
import           Raaz.Core.Write
import           Raaz.Hash.Sha.Util

import           Raaz.Hash.Internal

----------------------------- SHA256 -------------------------------------------

-- | The Sha256 hash value. Used in implementation of Sha224 as well.
data SHA256 = SHA256 (VU.Vector (BE Word32)) deriving Typeable

-- | Timing independent equality testing for sha256
instance Eq SHA256 where
 (==) (SHA256 g) (SHA256 h) = oftenCorrectEqVector g h

instance Storable SHA256 where
  sizeOf    _ = 8 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))

  peek = unsafeRunParser sha256parse . castPtr
    where sha256parse = SHA256 <$> unsafeParseStorableVector 8

  poke ptr (SHA256 v) = unsafeWrite writeSHA256 cptr
    where writeSHA256 = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore SHA256 where
  load = unsafeRunParser $ SHA256 <$> unsafeParseVector 8

  store cptr (SHA256 v) = unsafeWrite writeSHA256 cptr
    where writeSHA256 = writeVector v

instance Encodable SHA256

instance IsString SHA256 where
  fromString = fromBase16

instance Show SHA256 where
  show =  showBase16

instance Initialisable (HashMemory SHA256) () where
  initialise _ = initialise $ SHA256 $ VU.fromList [ 0x6a09e667
                                                   , 0xbb67ae85
                                                   , 0x3c6ef372
                                                   , 0xa54ff53a
                                                   , 0x510e527f
                                                   , 0x9b05688c
                                                   , 0x1f83d9ab
                                                   , 0x5be0cd19
                                                   ]

instance Primitive SHA256 where
  blockSize _                = BYTES 64
  type Implementation SHA256 = SomeHashI SHA256
  recommended  _             = SomeHashI $ cPortable

instance Hash SHA256 where
  additionalPadBlocks _ = 1

------------------- The portable C implementation ------------

cPortable :: HashI SHA256 (HashMemory SHA256)
cPortable = shaImplementation c_sha256_compress length64Write

foreign import ccall unsafe
  "raaz/hash/sha256/portable.h raazHashSha256PortableCompress"
  c_sha256_compress  :: Pointer -> Int -> Pointer -> IO ()
