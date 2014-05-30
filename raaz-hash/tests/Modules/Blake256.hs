module Modules.Blake256
       ( tests
       ) where

import           Control.Applicative
import qualified Data.ByteString       as B
import qualified Data.ByteString.Char8 as C8
import           Data.Default
import           Test.QuickCheck       (Arbitrary(..))

import Raaz.Test.Gadget

import Modules.Generic
import Raaz.Hash.Blake256.Internal

import           Data.Typeable
import           Raaz.Test.EndianStore
import           Raaz.Test.Cipher
import           Raaz.Test.Gadget
import           Test.Framework                       (Test, testGroup)


instance Arbitrary BLAKE256 where
  arbitrary = BLAKE256  <$> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary
                        <*> arbitrary


--tests = allHashTests (undefined ::BLAKE256) exampleStrings ++ [testCPortable]
--tests = allHashTests (undefined ::BLAKE256) exampleStrings 
tests = [  testStoreLoad h
         , testPadLengthVsPadding h
         , testLengthDivisibility h
         , testGroup unitTestName unitTests
        ] 
        where h = (undefined ::BLAKE256)
              unitTestName  = unwords [show $ typeOf h, "Unit tests"]
              unitTests     = testStandardHashValues h pairs
              pairs = exampleStrings


--testCPortable = testGadget g ref def "CPortable vs Reference"
--  where
--    g :: CPortable
--    g = undefined
--    ref :: Ref
--    ref = undefined

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
  ]
 where
   convertToByteString (a,b) = (C8.pack a, C8.pack b)
