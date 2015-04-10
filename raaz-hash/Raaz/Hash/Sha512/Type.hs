{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash.Sha512.Type
       ( SHA512(..)
       ) where

import qualified Data.Vector.Unboxed                  as VU
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

----------------------------- SHA512 -------------------------------------------

-- | The Sha512 hash value. Used in implementation of Sha384 as well.
newtype SHA512 = SHA512 (VU.Vector (BE Word64)) deriving ( Show, Typeable )

-- | Timing independent equality testing for sha512
instance Eq SHA512 where
 (==) (SHA512 g) (SHA512 h) = oftenCorrectEqVector g h

instance HasName SHA512

instance Storable SHA512 where
  sizeOf    _ = 8 * sizeOf (undefined :: (BE Word64))
  alignment _ = alignment  (undefined :: (BE Word64))

  peek ptr = do
    let parseSHA512 = unsafeParseStorableVector $ sizeOf (undefined :: SHA512)
        cptr = castPtr ptr
    parserV <- unsafeRunParser parseSHA512 cptr
    return $ SHA512 parserV

  poke ptr (SHA512 v) = unsafeWrite writeSHA512 cptr
    where writeSHA512 = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore SHA512 where
  load cptr = do
    let parseSHA512 = unsafeParseVector $ sizeOf (undefined :: SHA512)
    parserV <- unsafeRunParser parseSHA512 cptr
    return $ SHA512 parserV

  store cptr (SHA512 v) = unsafeWrite writeSHA512 cptr
    where writeSHA512 = writeVector v

instance Primitive SHA512 where
  blockSize _ = BYTES 128
  {-# INLINE blockSize #-}
  type Key SHA512 = SHA512

instance SafePrimitive SHA512

instance HasPadding SHA512 where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 16
  padding   = shaPadding   16
