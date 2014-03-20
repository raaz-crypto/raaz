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
import           Modules.Util

randcxt128 = BS.pack [1..32]
randcxt256 = BS.pack [1..48]

tests =
      [ testAll s20_128 "./ecryptTestData/salsa20_20.vectors" (keySize 16) "HGadget KEY128"
      , testAll s20_256 "./ecryptTestData/salsa20_20.vectors" (keySize 32) "HGadget KEY256"
      , encryptDecrypt s20_128 randcxt128
      , encryptDecrypt s20_256 randcxt256
      , testAll s12_128 "./ecryptTestData/salsa20_12.vectors" (keySize 16) "HGadget KEY128"
      , testAll s12_256 "./ecryptTestData/salsa20_12.vectors" (keySize 32) "HGadget KEY256"
      , encryptDecrypt s12_128 randcxt128
      , encryptDecrypt s12_256 randcxt256
      , testAll s8_128 "./ecryptTestData/salsa20_8.vectors" (keySize 16) "HGadget KEY128"
      , testAll s8_256 "./ecryptTestData/salsa20_8.vectors" (keySize 32) "HGadget KEY256"
      , encryptDecrypt s8_128 randcxt128
      , encryptDecrypt s8_256 randcxt256
      , testAll cs20_128 "./ecryptTestData/salsa20_20.vectors" (keySize 16) "HGadget KEY128"
      , testAll cs20_256 "./ecryptTestData/salsa20_20.vectors" (keySize 32) "HGadget KEY256"
      , encryptDecrypt cs20_128 randcxt128
      , encryptDecrypt cs20_256 randcxt256
      , testAll cs12_128 "./ecryptTestData/salsa20_12.vectors" (keySize 16) "HGadget KEY128"
      , testAll cs12_256 "./ecryptTestData/salsa20_12.vectors" (keySize 32) "HGadget KEY256"
      , encryptDecrypt cs12_128 randcxt128
      , encryptDecrypt cs12_256 randcxt256
      , testAll cs8_128 "./ecryptTestData/salsa20_8.vectors" (keySize 16) "HGadget KEY128"
      , testAll cs8_256 "./ecryptTestData/salsa20_8.vectors" (keySize 32) "HGadget KEY256"
      , encryptDecrypt cs8_128 randcxt128
      , encryptDecrypt cs8_256 randcxt256
      , testGroup "Salsa20/20 KEY128" $ cportableVsReference s20_128 cs20_128 randcxt128
      , testGroup "Salsa20/20 KEY256" $ cportableVsReference s20_256 cs20_256 randcxt256
      , testGroup "Salsa20/12 KEY128" $ cportableVsReference s12_128 cs12_128 randcxt128
      , testGroup "Salsa20/12 KEY256" $ cportableVsReference s12_256 cs12_256 randcxt256
      , testGroup "Salsa20/8 KEY128" $ cportableVsReference s8_128 cs8_128 randcxt128
      , testGroup "Salsa20/8 KEY256" $ cportableVsReference s8_256 cs8_256 randcxt256
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
        cs20_128 :: CGadget (Cipher (Salsa20 R20) KEY128 Encryption)
        cs20_128 = undefined
        cs20_256 :: CGadget (Cipher (Salsa20 R20) KEY256 Encryption)
        cs20_256 = undefined
        cs12_128 :: CGadget (Cipher (Salsa20 R12) KEY128 Encryption)
        cs12_128 = undefined
        cs12_256 :: CGadget (Cipher (Salsa20 R12) KEY256 Encryption)
        cs12_256 = undefined
        cs8_128 :: CGadget (Cipher (Salsa20 R8) KEY128 Encryption)
        cs8_128 = undefined
        cs8_256 :: CGadget (Cipher (Salsa20 R8) KEY256 Encryption)
        cs8_256 = undefined
