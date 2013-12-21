{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE TypeFamilies       #-}
module Raaz.Cipher.AES.Internal
       ( module Raaz.Cipher.AES.Ref.Type
       , Ref128(..)
       , Ref192(..)
       , Ref256(..)
       , CPortable128(..)
       , CPortable192(..)
       , CPortable256(..)
       , AES128(..)
       , AES192(..)
       , AES256(..)
       ) where

import Raaz.Cipher.AES.Ref.Type

import Data.Typeable
import Raaz.Memory

-- | Reference Implementation for AES128 in CBC Mode
data Ref128 m s = Ref128 (CryptoCell Expanded128, CryptoCell STATE)

-- | Reference Implementation for AES192 in CBC Mode
data Ref192 m s = Ref192 (CryptoCell Expanded192, CryptoCell STATE)

-- | Reference Implementation for AES256 in CBC Mode
data Ref256 m s = Ref256 (CryptoCell Expanded256, CryptoCell STATE)

-- | CPortable Implementation for AES128 in CBC Mode
data CPortable128 m s = CPortable128 (CryptoCell Expanded128, CryptoCell STATE)

-- | CPortable Implementation for AES192 in CBC Mode
data CPortable192 m s = CPortable192 (CryptoCell Expanded192, CryptoCell STATE)

-- | CPortable Implementation for AES256 in CBC Mode
data CPortable256 m s = CPortable256 (CryptoCell Expanded256, CryptoCell STATE)

data AES128 m s = AES128 deriving (Show,Eq,Typeable)

data AES192 m s = AES192 deriving (Show,Eq,Typeable)

data AES256 m s = AES256 deriving (Show,Eq,Typeable)
