{-# LANGUAGE CPP                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

-- | Internals of Sha384.
module Raaz.Hash.Sha384.Internal
       ( SHA384(..)
       ) where

import           Data.String
import           Data.Word
import           Foreign.Storable    ( Storable(..) )

import           Raaz.Core
import           Raaz.Hash.Internal


----------------------------- SHA384 -------------------------------------------

-- | The Sha384 hash value.
newtype SHA384 = SHA384 (Tuple 6 (BE Word64))
                 deriving (Eq, Equality, Storable, EndianStore)

instance Encodable SHA384

instance IsString SHA384 where
  fromString = fromBase16

instance Show SHA384 where
  show =  showBase16
instance Primitive SHA384 where
  type BlockSize SHA384      = 128
  type Implementation SHA384 = SomeHashI SHA384

instance Hash SHA384 where
  additionalPadBlocks _ = toEnum 1
