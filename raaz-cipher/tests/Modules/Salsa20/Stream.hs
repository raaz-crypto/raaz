{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE OverloadedStrings #-}

module Modules.Salsa20.Stream (tests) where

import           Data.ByteString                (ByteString,pack)
import qualified Data.ByteString                as BS
import qualified Data.ByteString.Char8          as B8
import           Data.Char
import           Data.Typeable

import           Test.Framework                 (Test,testGroup)
import           Test.Framework.Providers.HUnit (testCase)
import           Test.HUnit                     ((@=?))

import           Raaz.Test                      ()
import           Raaz.Test.Cipher
import           Raaz.Test.Gadget               (testGadget)
import           Raaz.Types
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import qualified Raaz.Util.ByteString           as BU

import           Raaz.Cipher.Salsa20.Internal
import           Raaz.Cipher.Salsa20            ()

import           Modules.EcryptTestParser
import           Modules.EcryptTest

randcxt128 = BS.pack [1..32]
randcxt256 = BS.pack [1..48]

tests =
      [ testAll s20_128 "./testData/salsa20_20.vectors" (keySize 16) "HGadget KEY128"
      , testAll s20_256 "./testData/salsa20_20.vectors" (keySize 32) "HGadget KEY256"
      , encryptDecrypt s20_128 randcxt128
      , encryptDecrypt s20_256 randcxt256
      , testAll s12_128 "./testData/salsa20_12.vectors" (keySize 16) "HGadget KEY128"
      , testAll s12_256 "./testData/salsa20_12.vectors" (keySize 32) "HGadget KEY256"
      , encryptDecrypt s12_128 randcxt128
      , encryptDecrypt s12_256 randcxt256
      , testAll s8_128 "./testData/salsa20_8.vectors" (keySize 16) "HGadget KEY128"
      , testAll s8_256 "./testData/salsa20_8.vectors" (keySize 32) "HGadget KEY256"
      , encryptDecrypt s8_128 randcxt128
      , encryptDecrypt s8_256 randcxt256

      ]
      where
        keySize :: BYTES Int -> EcryptTest -> Bool
        keySize w (EcryptTest _ k _ _ _) = BU.length k == w
        s20_128 :: HGadget (Cipher (Salsa20 R20) KEY128 Encryption)
        s20_128 = undefined
        s20_256 :: HGadget (Cipher (Salsa20 R20) KEY256 Encryption)
        s20_256 = undefined
        s12_128 :: HGadget (Cipher (Salsa20 R12) KEY128 Encryption)
        s12_128 = undefined
        s12_256 :: HGadget (Cipher (Salsa20 R12) KEY256 Encryption)
        s12_256 = undefined
        s8_128 :: HGadget (Cipher (Salsa20 R8) KEY128 Encryption)
        s8_128 = undefined
        s8_256 :: HGadget (Cipher (Salsa20 R8) KEY256 Encryption)
        s8_256 = undefined
