{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash.Sha256.Type
       ( SHA256(..)
       ) where

import qualified Data.Vector.Unboxed as VU
import           Data.Word
import           Data.Typeable       ( Typeable     )
import           Foreign.Ptr         ( castPtr      )
import           Foreign.Storable    ( Storable(..) )

import           Raaz.Core.Classes
import           Raaz.Core.Parse.Applicative
import           Raaz.Core.Primitives
import           Raaz.Core.Types
import           Raaz.Core.Write
import           Raaz.Hash.Sha.Util

----------------------------- SHA256 -------------------------------------------

-- | The Sha256 hash value. Used in implementation of Sha224 as well.
data SHA256 = SHA256 (VU.Vector (BE Word32)) deriving ( Show, Typeable )

-- | Timing independent equality testing for sha256
instance Eq SHA256 where
 (==) (SHA256 g) (SHA256 h) = oftenCorrectEqVector g h

instance HasName SHA256

instance Storable SHA256 where
  sizeOf    _ = 8 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))

  peek ptr = do
    let parseSHA256 = unsafeParseStorableVector $ sizeOf (undefined :: SHA256)
        cptr = castPtr ptr
    parserV <- unsafeRunParser parseSHA256 cptr
    return $ SHA256 parserV

  poke ptr (SHA256 v) = unsafeWrite writeSHA256 cptr
    where writeSHA256 = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore SHA256 where
  load cptr = do
    let parseSHA256 = unsafeParseVector $ sizeOf (undefined :: SHA256)
    parserV <- unsafeRunParser parseSHA256 cptr
    return $ SHA256 parserV

  store cptr (SHA256 v) = unsafeWrite writeSHA256 cptr
    where writeSHA256 = writeVector v

instance Primitive SHA256 where
  blockSize _ = BYTES 64
  {-# INLINE blockSize #-}
  type Key SHA256 = SHA256

instance SafePrimitive SHA256

instance HasPadding SHA256 where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 8
  padding   = shaPadding   8
