module Modules.Blake2s
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
import           Raaz.Hash.Blake2s.Internal

instance Arbitrary BLAKE2S where
  arbitrary = BLAKE2S   <$> arbitrary
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
        where h             = (undefined ::BLAKE2S)
              unitTestName  = unwords [show $ typeOf h, "Unit tests"]
              unitTests     = testStandardHashValues h pairs
              pairs         = exampleStrings


exampleStrings :: [(B.ByteString,B.ByteString)]
exampleStrings = map convertToByteString
  [ ( "hello"
    , "19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25" )
  , ( "blake2"
    , "03ff98699d53d8c2680f98e2557bd96c2e4e1f4610fedabba50c266d0988c74b" )
  , ( "The quick brown fox jumps over the lazy dog"
    , "606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812" )
  --, ( "HELP! I'm trapped in hash!"
  --  , "1e75db2a709081f853c2229b65fd1558540aa5e7bd17b04b9a4b31989effa711" )
  --, ( "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congu"
  --  , "5234baeebcd7c32fbffe863c9391acc7b3a77724b0cc2f8a7af5eed9a61f38ce" )
  , ( "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit. Donec et mollis dolor. Praesent et diam eget libero egestas mattis sit amet vitae augue. Nam tincidunt congue enim, ut porta lorem lacinia consectetur. Donec ut libero sed arcu vehicula ultricies a non tortor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean ut gravida lorem. Ut turpis felis, pulvinar a semper sed, adipiscing id dolor. Pellentesque auctor nisi id magna consequat sagittis. Curabitur dapibus enim sit amet elit pharetra tincidunt feugiat nisl imperdiet. Ut convallis libero in urna ultrices accumsan. Donec sed odio eros. Donec viverra mi quis quam pulvinar at malesuada arcu rhoncus. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. In rutrum accumsan ultricies. Mauris vitae nisi at sem facilisis semper ac in est."
    , "71d364433983776c6f5b9dd48dca4cd902dc6ea8e903bf6c3789a86eb3c64b96" )
  ]
 where
   convertToByteString (a,b) = (C8.pack a, C8.pack b)
