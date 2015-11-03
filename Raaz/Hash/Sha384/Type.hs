{-|

This module exposes the `SHA384` hash constructor. You would hardly
need to import the module directly as you would want to treat the
`SHA384` type as an opaque type for type safety. This module is
exported only for special uses like writing a test case or defining a
binary instance etc.

-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash.Sha384.Type
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
import           Raaz.Hash.Sha.Util

import           Raaz.Hash.Sha512.Type ( SHA512(..) )


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

instance Primitive SHA384 where
  blockSize _ = BYTES 128
  {-# INLINE blockSize #-}
  type Key SHA384 = SHA512

instance SafePrimitive SHA384

instance HasPadding SHA384 where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 16
  padding   = shaPadding   16
