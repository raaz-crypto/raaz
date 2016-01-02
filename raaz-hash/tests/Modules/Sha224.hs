{-# LANGUAGE OverloadedStrings #-}
module Modules.Sha224
       ( tests
       ) where

import           Control.Applicative
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.Vector.Unboxed   as VU
import           Test.QuickCheck       ( Arbitrary(..) )
import           Test.QuickCheck.Arbitrary

import Raaz.Core.Memory
import Raaz.Core.Test.Gadget

import Modules.Generic
import Raaz.Hash.Sha224.Internal
import Raaz.Hash.Sha256.Internal

instance Arbitrary SHA224 where
  arbitrary = SHA224 . VU.fromList <$> vector 7

tests = allHashTests (undefined :: SHA224) (undefined :: (MemoryCell SHA256)) exampleStrings

exampleStrings :: [(B.ByteString,B.ByteString)]
exampleStrings =
