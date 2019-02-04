{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE CPP                  #-}

module Raaz.Mac.Poly1305Spec where

import Tests.Core
import Poly1305.Interface

macsTo :: ByteString -> Poly1305 -> Key Poly1305 -> Spec
macsTo inp expected key =  it msg $ result `shouldBe` expected
  where result = auth key inp
        msg  = unwords [ "with key"
                       , shortened $ show key
                       , "macs"
                       , shortened $ show inp
                       , "to"
                       , shortened $ show expected
                       ]
spec :: Spec
spec = do
  describe "Poly1305" $
    basicEndianSpecs (undefined :: Poly1305)
  describe "R" $
    basicEndianSpecs (undefined :: R)
  describe "S" $
    basicEndianSpecs (undefined :: S)


  with ( "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8"
       , "01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"
       ) $ ( "Cryptographic Forum Research Group" :: ByteString)
    `macsTo` ("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9" :: Poly1305)
