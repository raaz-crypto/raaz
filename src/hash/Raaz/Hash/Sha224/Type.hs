{-|

This module exposes the `SHA224` hash constructor. You would hardly
need to import the module directly as you would want to treat the
`SHA224` type as an opaque type for type safety. This module is
exported only for special uses like writing a test case or defining a
binary instance etc.

-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash.Sha224.Type
       ( SHA224(..)
       ) where

import           Control.Applicative ( (<$>) )
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

import           Raaz.Hash.Sha256.Type
import           Raaz.Hash.Sha256.Instance ()

----------------------------- SHA224 -------------------------------------------

-- | Sha224 hash value which consist of 7 32bit words.
data SHA224 = SHA224 (VU.Vector (BE Word32)) deriving ( Show, Typeable )

-- | Timing independent equality testing for sha224
instance Eq SHA224 where
 (==) (SHA224 g) (SHA224 h) = oftenCorrectEqVector g h

instance HasName SHA224

instance Storable SHA224 where
  sizeOf    _ = 7 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))

  peek = unsafeRunParser sha224parse . castPtr
    where sha224parse = SHA224 <$> unsafeParseStorableVector 7

  poke ptr (SHA224 v) = unsafeWrite writeSHA224 cptr
    where writeSHA224 = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore SHA224 where
  load = unsafeRunParser $ SHA224 <$> unsafeParseVector 7

  store cptr (SHA224 v) = unsafeWrite writeSHA224 cptr
    where writeSHA224 = writeVector v

instance Primitive SHA224 where
  blockSize _ = BYTES 64
  {-# INLINE blockSize #-}
  type Key SHA224 = SHA256

instance SafePrimitive SHA224

instance HasPadding SHA224 where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 8
  padding   = shaPadding   8
