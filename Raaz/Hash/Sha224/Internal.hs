{-|

This module exposes the `SHA224` hash constructor. You would hardly
need to import the module directly as you would want to treat the
`SHA224` type as an opaque type for type safety. This module is
exported only for special uses like writing a test case or defining a
binary instance etc.

-}

{-# LANGUAGE CPP                        #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Hash.Sha224.Internal
       ( SHA224(..)
       ) where

import           Data.String
import           Data.Word
import           Foreign.Storable          ( Storable )

import           Raaz.Core
import           Raaz.Hash.Internal

----------------------------- SHA224 -------------------------------------------

-- | Sha224 hash value which consist of 7 32bit words.
newtype SHA224 = SHA224 (Tuple 7 (BE Word32))
            deriving (Eq, Equality, Storable, EndianStore)

instance Encodable SHA224

instance IsString SHA224 where
  fromString = fromBase16

instance Show SHA224 where
  show =  showBase16

instance Primitive SHA224 where
  type BlockSize SHA224      = 64
  type Implementation SHA224 = SomeHashI SHA224

instance Hash SHA224 where
  additionalPadBlocks _ = toEnum 1
