{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings   #-}
module Raaz.Core.Encode.Base16Spec where


import Control.Applicative
import Data.ByteString hiding (concat)
import Data.String
import Data.Word
import Numeric
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Raaz.Core.Encode.Base16
import Arbitrary()

instance Arbitrary Base16 where
  arbitrary =  fromString <$> evenLengthString
    where genHexDigit      =  oneof [ choose ('a','f'), choose('0','9') ]
          twoString        =  do x <- genHexDigit
                                 y <- genHexDigit
                                 return [x,y]
          evenLengthString =  concat <$> listOf twoString


spec :: Spec
spec = do
  context "for ByteStrings" $ do
    prop "fromBase16 . base16 == id" $ \ (x :: ByteString) -> fromBase16 (base16 x)               == x
    prop "base16 . fromBase16 == id" $ \ (x :: Base16)     -> base16 (fromBase16 x :: ByteString) == x

  let range      = (0x10, 0xff :: Word8)
      genInRange = choose range
      in do
    context ("for bytes in the range " ++ show range) $ do
      it "base16 and showHex should match" $
        forAll genInRange $ \ (x :: Word8) -> base16 (singleton x) == fromString (showHex x "")
