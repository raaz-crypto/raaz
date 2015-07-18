module Modules.Blake256
       ( tests
       ) where

import           Control.Applicative
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.Vector.Unboxed   as VU
import           Data.Typeable
import           Data.Word
import           Test.QuickCheck       (Arbitrary(..))
import           Test.Framework        (Test, testGroup)
import           Test.QuickCheck.Arbitrary

import           Test.EndianStore
import           Test.Cipher
import           Test.Gadget

import           Modules.Generic
import           Raaz.Core.Memory
import           Raaz.Core.Types
import           Raaz.Hash.Blake256.Internal

instance Arbitrary BLAKE256 where
  arbitrary = BLAKE256 . VU.fromList <$> vector 8

tests = allHashTests (undefined :: BLAKE256) (undefined :: (MemoryCell BLAKE256, MemoryCell Salt, MemoryCell (BITS Word64))) exampleStrings

{-tests = [ testStoreLoad h
        , testPadLengthVsPadding h
        , testLengthDivisibility h
        , testGroup unitTestName unitTests
        ]
        where h             = (undefined ::BLAKE256)
              unitTestName  = unwords [show $ typeOf h, "Unit tests"]
              unitTests     = testStandardHashValues h pairs
              pairs         = exampleStrings-}


exampleStrings :: [(B.ByteString,B.ByteString)]
exampleStrings = map convertToByteString
  [ ( "BLAKE"
    , "07663e00cf96fbc136cf7b1ee099c95346ba3920893d18cc8851f22ee2e36aa6" )
  , ( "Go"
    , "fd7282ecc105ef201bb94663fc413db1b7696414682090015f17e309b835f1c2" )
  , ( "The quick brown fox jumps over the lazy dog"
    , "7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7" )
  , ( "HELP! I'm trapped in hash!"
    , "1e75db2a709081f853c2229b65fd1558540aa5e7bd17b04b9a4b31989effa711" )
  , ( "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congu"
    , "af95fffc7768821b1e08866a2f9f66916762bfc9d71c4acb5fd515f31fd6785a" )
  , ( "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ut gravida lorem. Ut turpis felis, pulvinar a semper sed, adipiscing id dolor. Pellentesque auctor nisi id magna consequat sagittis. Curabitur dapibus enim sit amet elit pharetra tincidunt feugiat nisl imperdiet. Ut convallis libero in urna ultrices accumsan. Donec sed odio eros. Donec viverra mi quis quam pulvinar at malesuada arcu rhoncus. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. In rutrum accumsan ultricies. Mauris vitae nisi at sem facilisis semper ac in est."
    , "4181475cb0c22d58ae847e368e91b4669ea2d84bcd55dbf01fe24bae6571dd08" )
  ]
 where
   convertToByteString (a,b) = (C8.pack a, C8.pack b)
