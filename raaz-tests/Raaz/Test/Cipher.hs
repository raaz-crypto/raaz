{-|

Generic tests for Hash implementations.

-}
{-# LANGUAGE FlexibleContexts #-}

module Raaz.Test.Cipher
       ( testStandardCiphers
       ) where

import qualified Data.ByteString as B
import Test.Framework(Test)
import Test.HUnit ((~?=), test, (~:) )
import Test.Framework.Providers.HUnit(hUnitTestToTests)

import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Test.Instances()
import Raaz.Test.Hash (shorten)
import Raaz.Util.ByteString (hex)

-- | Checks standard plaintext - ciphertext for the given cipher
testStandardCiphers  :: (Gadget g, Initializable (PrimitiveOf g))
                     => g                                          -- ^ Gadget
                     -> [(B.ByteString,B.ByteString,B.ByteString)] -- ^ (key, planetext,ciphertest)
                     -> String                                     -- ^ Header
                     -> [Test]
testStandardCiphers g triples msg = hUnitTestToTests . test $ map checkCipher triples
  where getCipher k v = hex $ unsafeApply g k v nb
          where nb = fromIntegral $
                  B.length v `div` (fromIntegral $ blockSize $ getPrim g)
        getPrim :: (Gadget g) => g -> PrimitiveOf g
        getPrim _ = undefined
        label a   = msg ++ " " ++ shorten (show $ hex a)
        checkCipher (k,a,b) = label a ~: getCipher k a ~?= hex b
