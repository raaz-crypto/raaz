module Modules.Blake2b
       ( tests
       ) where

import           Control.Applicative
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as C8
import           Data.Default
import           Data.Typeable
import           Test.QuickCheck       (Arbitrary(..))
import           Test.Framework        (Test, testGroup)

import           Raaz.Core.Test.EndianStore
import           Raaz.Core.Test.Cipher
import           Raaz.Core.Test.Gadget

import           Modules.Generic
import           Raaz.Hash.Blake2b.Internal

instance Arbitrary BLAKE2B where
  arbitrary = BLAKE2B  <$> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        
--tests = allHashTests (undefined ::BLAKE2B) exampleStrings

tests = [ testStoreLoad h
        , testPadLengthVsPadding h
        , testLengthDivisibility h
        , testGroup unitTestName unitTests
        ]
        where h             = (undefined ::BLAKE2B)
              unitTestName  = unwords [show $ typeOf h, "Unit tests"]
              unitTests     = testStandardHashValues h pairs
              pairs         = exampleStrings


exampleStrings :: [(B.ByteString,B.ByteString)]
exampleStrings = map convertToByteString
  [ ( "hello"
    , "e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65ba1e1b146aeb6bd0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94" )
  , ( "blake2"
    , "4245af08b46fbb290222ab8a68613621d92ce78577152d712467742417ebc1153668f1c9e1ec1e152a32a9c242dc686d175e087906377f0c483c5be2cb68953e" )
  , ( "The quick brown fox jumps over the lazy dog"
    , "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918" )
  --, ( "HELP! I'm trapped in hash!"
  --  , "1e75db2a709081f853c2229b65fd1558540aa5e7bd17b04b9a4b31989effa711" )
  , ( "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congu"
    , "391fbc4f9fdaaf9a845129b62d9365f3293ec23b407da1f2a854b0b59b37f9cc60986bce95be1881b8320eec5925a0402fb084b4096f6fa0e6ddeecbd22c3d9b" )
  , ( "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ut gravida lorem. Ut turpis felis, pulvinar a semper sed, adipiscing id dolor. Pellentesque auctor nisi id magna consequat sagittis. Curabitur dapibus enim sit amet elit pharetra tincidunt feugiat nisl imperdiet. Ut convallis libero in urna ultrices accumsan. Donec sed odio eros. Donec viverra mi quis quam pulvinar at malesuada arcu rhoncus. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. In rutrum accumsan ultricies. Mauris vitae nisi at sem facilisis semper ac in est."
    , "69deddb90547775205b78a7ccdd4671151acb729006752b73f37c982d425de8116cba9272023f92a55ba2c3cd5a946c4a4d53e081ee66e2fd1d49b968fe83ff0" )
  ]
 where
   convertToByteString (a,b) = (C8.pack a, C8.pack b)
