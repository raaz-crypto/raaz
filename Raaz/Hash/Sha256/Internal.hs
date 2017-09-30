{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

-- | Internals of Sha256.
module Raaz.Hash.Sha256.Internal
       ( SHA256(..)
       ) where


import Data.String
import Data.Word
import Foreign.Storable    ( Storable )

import Raaz.Core

import Raaz.Hash.Internal

----------------------------- SHA256 -------------------------------------------

-- | The Sha256 hash value.
newtype SHA256 = SHA256 (Tuple 8 (BE Word32))
              deriving (Eq, Equality, Storable, EndianStore)

instance Encodable SHA256

instance IsString SHA256 where
  fromString = fromBase16

instance Show SHA256 where
  show =  showBase16

instance Initialisable (HashMemory SHA256) () where
  initialise _ = initialise $ SHA256 $ unsafeFromList [ 0x6a09e667
                                                      , 0xbb67ae85
                                                      , 0x3c6ef372
                                                      , 0xa54ff53a
                                                      , 0x510e527f
                                                      , 0x9b05688c
                                                      , 0x1f83d9ab
                                                      , 0x5be0cd19
                                                      ]

instance Primitive SHA256 where
  type BlockSize SHA256      = 64
  type Implementation SHA256 = SomeHashI SHA256

instance Hash SHA256 where
  additionalPadBlocks _ = toEnum 1
