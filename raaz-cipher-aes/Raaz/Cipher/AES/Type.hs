{-# LANGUAGE DataKinds      #-}
{-# LANGUAGE KindSignatures #-}

module Raaz.Cipher.AES.Type where

import Raaz.Primitives.Cipher

data AES128 (m :: Mode) (s :: Stage) = AES128 deriving (Show,Eq)

data AES192 (m :: Mode) (s :: Stage) = AES192 deriving (Show,Eq)

data AES256 (m :: Mode) (s :: Stage) = AES256 deriving (Show,Eq)
