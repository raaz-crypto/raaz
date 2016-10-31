{-# LANGUAGE DataKinds                        #-}
{-# LANGUAGE KindSignatures                   #-}
{-# LANGUAGE GeneralizedNewtypeDeriving       #-}
{-# LANGUAGE ForeignFunctionInterface         #-}
{-# LANGUAGE FlexibleInstances                #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE TypeFamilies                     #-}

module Raaz.Cipher.ChaCha20.Internal
       ( ChaCha20(..), Counter(..), IV(..), KEY(..)
       ) where

import Data.Word
import Data.String
import Foreign.Storable

import Raaz.Core
import Raaz.Cipher.Internal

-- | The chacha20 stream cipher.


-- | The word type
type WORD     = LE Word32

-- | The IV for the chacha20
newtype IV       = IV (Tuple 3 (LE Word32))     deriving (Storable, EndianStore)

instance Encodable IV

instance Show IV where
  show = showBase16
instance IsString IV where
  fromString = fromBase16

-- | The counter type for chacha20
newtype Counter  = Counter (LE Word32) deriving (Num, Storable, EndianStore, Show)


-- | The key type.
newtype KEY      = ChaCha20Key (Tuple 8 WORD) deriving (Storable, EndianStore)

instance Encodable KEY

instance Show KEY where
  show = showBase16

instance IsString KEY where
  fromString = fromBase16


data ChaCha20 = ChaCha20

instance Primitive ChaCha20 where
  blockSize _ = BYTES 64
  type Implementation ChaCha20 = SomeCipherI ChaCha20

instance Symmetric ChaCha20 where
  type Key ChaCha20 = (KEY, IV)

instance Cipher ChaCha20

instance StreamCipher ChaCha20
