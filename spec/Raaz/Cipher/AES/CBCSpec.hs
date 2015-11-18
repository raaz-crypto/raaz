{-# LANGUAGE OverloadedStrings #-}

module Raaz.Cipher.AES.CBCSpec where

import Test.Hspec
import qualified Generic.Cipher as GC

spec :: Spec
spec =  describe "AES CBC tests" $ do
  it "unit tests" $ pendingWith "Better interface is being hacked"
