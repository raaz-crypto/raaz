{-|

Generic tests for Hash implementations.

-}
{-# LANGUAGE FlexibleContexts #-}

module Raaz.Test.Cipher
       ( testStandardCiphers
       , shorten
       ) where

import qualified Data.ByteString                as BS
import           Data.ByteString.Internal       (ByteString,create)
import           Foreign.Ptr
import           System.IO.Unsafe               (unsafePerformIO)
import           Test.Framework                 (Test)
import           Test.HUnit                     ((~?=), test, (~:) )
import           Test.Framework.Providers.HUnit (hUnitTestToTests)

import           Raaz.ByteSource
import           Raaz.Memory
import           Raaz.Types
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Util.ByteString           (hex)

-- | Checks standard plaintext - ciphertext for the given cipher
testStandardCiphers  :: (CipherGadget g)
                     => g Encryption
                     -> [(ByteString,ByteString,ByteString)] -- ^ (key, planetext,ciphertest)
                     -> String                               -- ^ Header
                     -> [Test]
testStandardCiphers ge triples msg = hUnitTestToTests $ test $ map checkCipher triples
  where label a    = msg ++ " " ++ shorten (show $ hex a)
        checkCipher (k,a,b) =
          label a ~: test  ["Encryption" ~: (encrypt ge k a) ~?= b
                           ,"Decryption" ~: (decrypt (dec ge) k b) ~?= a]
        dec :: (CipherGadget g) => g Encryption-> (g Decryption)
        dec _ = undefined

-- | Similar to the above function except this returns strict
-- ByteString rather than Lazy ByteString and works on finite
-- ByteSource alone.
unsafeTransformUnsafeGadget' :: Gadget g
                             => g          -- ^ Gadget
                             -> ByteString -- ^ The byte source
                             -> IO ByteString
{-# INLINEABLE unsafeTransformUnsafeGadget' #-}
unsafeTransformUnsafeGadget' g src = do
  let size = BS.length src
  create size (with (BYTES size) . castPtr)
  where with size cptr = do
          _ <- fillBytes size src cptr
          apply g (cryptoCoerce size) cptr

-- | Encrypts/Decrypts a bytestring using the given gadget. It only
-- encrypts in multiple of BlockSize, so user must ensure that.
createAndApply' :: (Gadget g, Initializable (PrimitiveOf g))
                => g
                -> ByteString               -- ^ Key and IV
                -> ByteString               -- ^ Plain data
                -> IO ByteString            -- ^ Encrypted data
createAndApply' g key src = do
  ng <- createGadget g
  initialize ng (getIV key)
  unsafeTransformUnsafeGadget' ng src
    where
      createGadget :: (Gadget g) => g -> IO g
      createGadget _ = newGadget
{-# INLINEABLE createAndApply' #-}

encrypt :: CipherGadget g => g Encryption -> ByteString -> ByteString -> ByteString
encrypt g k = unsafePerformIO . createAndApply' g k
{-# NOINLINE encrypt #-}

decrypt :: CipherGadget g => g Decryption -> ByteString -> ByteString -> ByteString
decrypt g k = unsafePerformIO . createAndApply' g k
{-# NOINLINE decrypt #-}

-- | While displaying the input truncate it to these many characters.
maxLength :: Int
maxLength = 10

-- | This is to shorten the large strings while displaying unit test results
shorten :: String -> String
shorten str | l <= maxLength = str
            | otherwise      = take maxLength str ++ "..."
                             ++ "("
                             ++ show (l - maxLength)
                             ++ " more chars)"
  where l = length str
