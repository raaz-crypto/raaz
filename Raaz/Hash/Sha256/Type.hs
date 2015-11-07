{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash.Sha256.Type
       ( SHA256(..)
       ) where

import           Control.Applicative ( (<$>) )
import           Data.String
import qualified Data.Vector.Unboxed as VU
import           Data.Word
import           Data.Typeable       ( Typeable     )
import           Foreign.Ptr         ( castPtr      )
import           Foreign.Storable    ( Storable(..) )

import           Raaz.Core
import           Raaz.Core.Parse.Applicative
import           Raaz.Core.Write
import           Raaz.Hash.Sha.Util

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

instance Primitive SHA256 where
  blockSize _ = BYTES 64
  {-# INLINE blockSize #-}
  type Key SHA256 = SHA256

instance SafePrimitive SHA256

instance HasPadding SHA256 where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 8
  padding   = shaPadding   8
