{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

{-|

This module exposes the `SHA1` hash constructor. You would hardly need
to import the module directly as you would want to treat the `SHA1`
type as an opaque type for type safety. This module is exported only
for special uses like writing a test case or defining a binary
instance etc.

-}
module Raaz.Hash.Sha1.Type
       ( SHA1(..)
       ) where

import           Control.Applicative ( (<$>) )
import qualified Data.Vector.Unboxed                  as VU
import           Data.Word
import           Data.Typeable       ( Typeable     )
import           Foreign.Ptr         ( castPtr      )
import           Foreign.Storable    ( Storable(..) )

import           Raaz.Core
import           Raaz.Core.Parse.Applicative
import           Raaz.Core.Write
import           Raaz.Hash.Sha.Util

-- | The SHA1 hash value.
newtype SHA1 = SHA1 (VU.Vector (BE Word32)) deriving ( Show, Typeable )

-- | Timing independent equality testing.
instance Eq SHA1 where
 (==) (SHA1 g) (SHA1 h) = oftenCorrectEqVector g h

instance HasName SHA1

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

instance Encode SHA1

instance Primitive SHA1 where
  blockSize _ = BYTES 64
  {-# INLINE blockSize #-}
  type Key SHA1 = SHA1

instance SafePrimitive SHA1

instance HasPadding SHA1 where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 8
  padding   = shaPadding   8
