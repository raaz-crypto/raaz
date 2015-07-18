{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies      #-}

module Modules.AES.Defaults where

import           Data.ByteString             ( ByteString, pack )
import qualified Data.ByteString             as BS
import           Data.Typeable

import           Test.Framework              ( Test, testGroup  )

import           Test              ()
import           Test.Cipher
import           Test.Gadget       ( testGadget       )
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Util.ByteString

import           Raaz.Cipher.AES.Type
import           Raaz.Cipher.AES.Internal

import           Modules.AES.Block           ()
import           Modules.Util

testsDefault p s128 s192 s256 =
      [
        testStandardCiphers (toH $ p128 p) s128
      , testStandardCiphers (toH $ p192 p) s192
      , testStandardCiphers (toH $ p256 p) s256
      , testStandardCiphers (toC $ p128 p) s128
      , testStandardCiphers (toC $ p192 p) s192
      , testStandardCiphers (toC $ p256 p) s256
      , cportableVsReference (toH $ p128 p)
                             (toC $ p128 p)
                             (first $ head s128)
      , cportableVsReference (toH $ p192 p)
                             (toC $ p192 p)
                             (first $ head s192)
      , cportableVsReference (toH $ p256 p)
                             (toC $ p256 p)
                             (first $ head s256)
      ]
      where
        first (a,_,_) = a
        toH :: AES mode k -> HAESGadget mode k EncryptMode
        toH _ = undefined
        toC :: AES mode k -> CAESGadget mode k EncryptMode
        toC _ = undefined
        p128 :: AES mode key -> AES mode KEY128
        p128 = undefined
        p192 :: AES mode key -> AES mode KEY192
        p192 = undefined
        p256 :: AES mode key -> AES mode KEY256
        p256 = undefined
