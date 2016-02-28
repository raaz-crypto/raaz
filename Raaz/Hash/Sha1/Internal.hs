{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

{-|

This module exposes the `SHA1` hash constructor. You would hardly need
to import the module directly as you would want to treat the `SHA1`
type as an opaque type for type safety. This module is exported only
for special uses like writing a test case or defining a binary
instance etc.

-}

module Raaz.Hash.Sha1.Internal (SHA1(..)) where

import           Data.String
import           Data.Word
import           Foreign.Storable    ( Storable(..) )

import           Raaz.Core
import           Raaz.Hash.Sha.Util

import           Raaz.Hash.Internal

-- | The cryptographic hash SHA1.
newtype SHA1 = SHA1 (Tuple 5 (BE Word32))
             deriving (Storable, EndianStore, Equality, Eq)

{--
-- | Timing independent equality testing.
instance Eq SHA1 where
 (==) (SHA1 g) (SHA1 h) = oftenCorrectEqVector g h

instance Storable SHA1 where
  sizeOf    _ = 5 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))
  peek  = unsafeRunParser sha1parse . castPtr
    where sha1parse = SHA1 <$> unsafeParseStorableVector 5

  poke ptr (SHA1 v) = unsafeWrite writeSHA1 cptr
    where writeSHA1 = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore SHA1 where
  load = unsafeRunParser $ SHA1 <$> unsafeParseVector 5

  store cptr (SHA1 v) = unsafeWrite writeSHA1 cptr
    where writeSHA1 = writeVector v

-}
instance Encodable SHA1

instance IsString SHA1 where
  fromString = fromBase16

instance Show SHA1 where
  show = showBase16

instance Initialisable (HashMemory SHA1) () where
  initialise _ = initialise $ SHA1 $ unsafeFromList [ 0x67452301
                                                    , 0xefcdab89
                                                    , 0x98badcfe
                                                    , 0x10325476
                                                    , 0xc3d2e1f0
                                                    ]


instance Primitive SHA1 where
  blockSize _              = BYTES 64
  type Implementation SHA1 = SomeHashI SHA1

  recommended  _           = SomeHashI cPortable

instance Hash SHA1 where
  additionalPadBlocks _ = 1

------------------- The portable C implementation ------------

cPortable :: HashI SHA1 (HashMemory SHA1)
cPortable = shaImplementation c_sha1_compress length64Write

foreign import ccall unsafe
  "raaz/hash/sha1/portable.h raazHashSha1PortableCompress"
  c_sha1_compress  :: Pointer -> Int -> Pointer -> IO ()
