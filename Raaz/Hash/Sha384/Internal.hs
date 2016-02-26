{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

module Raaz.Hash.Sha384.Internal
       ( SHA384(..)
       ) where

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
import           Raaz.Hash.Internal
import qualified Raaz.Hash.Sha512.Internal as Sha512I
import           Raaz.Hash.Sha512.Internal ( SHA512(..) )


----------------------------- SHA384 -------------------------------------------

-- | The Sha384 hash value.
newtype SHA384 = SHA384 (VU.Vector (BE Word64)) deriving Typeable

-- | Timing independent equality testing for sha384
instance Eq SHA384 where
 (==) (SHA384 g) (SHA384 h) = oftenCorrectEqVector g h

instance Storable SHA384 where
  sizeOf    _ = 6 * sizeOf (undefined :: (BE Word64))
  alignment _ = alignment  (undefined :: (BE Word64))

  peek = unsafeRunParser sha384parse . castPtr
    where sha384parse = SHA384 <$> unsafeParseStorableVector 6

  poke ptr (SHA384 v) = unsafeWrite writeSHA384 cptr
    where writeSHA384 = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore SHA384 where
  load = unsafeRunParser $ SHA384 <$> unsafeParseVector 6

  store cptr (SHA384 v) = unsafeWrite writeSHA384 cptr
    where writeSHA384 = writeVector v


instance Encodable SHA384

instance IsString SHA384 where
  fromString = fromBase16

instance Show SHA384 where
  show =  showBase16

newtype SHA384Memory = SHA384Memory { unSHA384Mem :: HashMemory SHA512 }

instance Memory SHA384Memory where
  memoryAlloc   = SHA384Memory <$> memoryAlloc
  underlyingPtr = underlyingPtr . unSHA384Mem

instance Initialisable SHA384Memory () where
  initialise _ = liftSubMT unSHA384Mem
                 $ initialise
                 $ SHA512
                 $ VU.fromList [ 0xcbbb9d5dc1059ed8
                               , 0x629a292a367cd507
                               , 0x9159015a3070dd17
                               , 0x152fecd8f70e5939
                               , 0x67332667ffc00b31
                               , 0x8eb44a8768581511
                               , 0xdb0c2e0d64f98fa7
                               , 0x47b5481dbefa4fa4
                               ]

instance Extractable SHA384Memory SHA384 where
  extract = trunc <$> liftSubMT unSHA384Mem extract
    where trunc :: SHA512 -> SHA384
          trunc (SHA512 v) = SHA384 (VU.slice 0 6 v)

instance Primitive SHA384 where
  blockSize _ = BYTES 128
  type Implementation SHA384 = SomeHashI SHA384
  recommended  _             = SomeHashI cPortable

instance Hash SHA384 where
  additionalPadBlocks _ = 1

------------------- The portable C implementation ------------

cPortable :: HashI SHA384 SHA384Memory
cPortable = truncatedI fromIntegral unSHA384Mem Sha512I.cPortable
