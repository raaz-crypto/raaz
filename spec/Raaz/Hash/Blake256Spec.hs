
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Raaz.Hash.Blake256Spec where

import Control.Applicative
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

import Data.ByteString.Char8
import Raaz.Core as RC
-- import Raaz.Hash.Blake256.Internal
import Generic.EndianStore
import qualified Generic.Hash as GH
import Arbitrary
{-
import Data.Word
instance Arbitrary BLAKE256 where
  arbitrary = BLAKE256 <$> arbitraryVector 8

hashesTo :: ByteString -> BLAKE256 -> Spec
hashesTo = GH.hashesTo

pad     :: BITS Word64 -> ByteString
padLen  :: BITS Word64 -> BYTES Int
blockSz :: BYTES Int


pad     = padding   (undefined :: BLAKE256)
padLen  = padLength (undefined :: BLAKE256)
blockSz = blockSize (undefined :: BLAKE256)
-}
spec :: Spec
spec = it "Blake tests" $ pendingWith "Blake"
{-
spec =  do

  prop "store followed by load returns original value" $ \ (x :: BLAKE256) ->
    storeAndThenLoad x `shouldReturn` x

  prop "checks that the padding string has the same length as padLength" $
    \ w -> padLen w == (RC.length $ pad w)

  prop "length after padding should be an integral multiple of block size" $
    \ w -> (padLen w + bitsQuot w) `rem` blockSz == 0
  --
  -- Some unit tests
  --
  "BLAKE" `hashesTo` "07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6"

  "Go" `hashesTo` "fd7282ecc105ef201bb94663fc413db1b7696414682090015f17e309b835f1c2"

  "The quick brown fox jumps over the lazy dog" `hashesTo` "7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7"

  "HELP! I'm trapped in hash!" `hashesTo` "1e75db2a709081f853c2229b65fd1558540aa5e7bd17b04b9a4b31989effa711"

  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congu"
    `hashesTo` "af95fffc7768821b1e08866a2f9f66916762bfc9d71c4acb5fd515f31fd6785a"

  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ut gravida lorem. Ut turpis felis, pulvinar a semper sed, adipiscing id dolor. Pellentesque auctor nisi id magna consequat sagittis. Curabitur dapibus enim sit amet elit pharetra tincidunt feugiat nisl imperdiet. Ut convallis libero in urna ultrices accumsan. Donec sed odio eros. Donec viverra mi quis quam pulvinar at malesuada arcu rhoncus. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. In rutrum accumsan ultricies. Mauris vitae nisi at sem facilisis semper ac in est." `hashesTo`
    "4181475cb0c22d58ae847e368e91b4669ea2d84bcd55dbf01fe24bae6571dd08"
-}
