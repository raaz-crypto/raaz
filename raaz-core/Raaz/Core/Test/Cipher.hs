{-|

Generic tests for Hash implementations.

-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies     #-}

module Raaz.Core.Test.Cipher
       ( testStandardCiphers
       , applyGadget
       , encryptDecrypt
       , unitTests
       , shorten
       ) where

import qualified Data.ByteString                as BS
import           Data.ByteString.Internal       (ByteString,create)
import           Foreign.Ptr
import           System.IO.Unsafe               (unsafePerformIO)
import           Test.Framework                 (Test, testGroup)
import           Test.HUnit                     ((~?=), test, (~:) )
import           Test.Framework.Providers.HUnit (hUnitTestToTests)

import           Raaz.Core.ByteSource
import           Raaz.Core.Types
import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Util.ByteString           (hex)
import           Raaz.Serialize
import           Raaz.Core.Test.Gadget


-- | Stansdard tests for ciphers
testStandardCiphers :: ( HasName g
                       , HasName (Inverse g)
                       , Cipher (PrimitiveOf g)
                       , CryptoInverse g
                       , PrimitiveOf g ~ PrimitiveOf (Inverse g)
                       )
                    => g
                    -> [(ByteString,ByteString,ByteString)] -- ^ (key, planetext, ciphertext)
                    -> Test
testStandardCiphers g vec = testGroup name [ unitTests g vec
                                           , encryptDecrypt g testiv
                                           ]
  where
    name = getName g
    (testiv, _ , _) = head vec

-- | Checks standard plaintext - ciphertext for the given cipher
unitTests  :: ( HasName g
              , HasName (Inverse g)
              , CryptoInverse g
              , PrimitiveOf g ~ PrimitiveOf (Inverse g)
              , Cipher (PrimitiveOf g)
              )
           => g
           -> [(ByteString,ByteString,ByteString)] -- ^ (key, planetext,ciphertext)
           -> Test
unitTests ge triples = testGroup "Unit tests" $ hUnitTestToTests $ test $ map checkCipher triples
  where label a = shorten (show $ hex a)
        checkCipher (bk,a,b) =
          label a ~: test  ["Encryption" ~: (applyGadget ge ek a) ~?= b
                           ,"Decryption" ~: (applyGadget (inverse ge) dk b) ~?= a]
          where
            ek = cipherCxt $ fromByteString bk
            dk = cipherCxt $ fromByteString bk


-- | Checks if decrypt . encrypt == id
encryptDecrypt :: ( HasName g
                  , HasName (Inverse g)
                  , Cipher (PrimitiveOf g)
                  , PrimitiveOf g ~ PrimitiveOf (Inverse g)
                  , CryptoInverse g
                  )
               => g
               -> ByteString  -- ^ Context in ByteString
               -> Test
encryptDecrypt g bscxt = testInverse g (inverse g) (cipherCxt $ fromByteString bscxt)
                                                   (cipherCxt $ fromByteString bscxt)

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
          apply g (roundFloor size) cptr

-- | Encrypts/Decrypts a bytestring using the given gadget. It only
-- encrypts in multiple of BlockSize, so user must ensure that.
createAndApply' :: Gadget g
                => g
                -> Cxt (PrimitiveOf g)      -- ^ Key and IV
                -> ByteString               -- ^ Plain data
                -> IO ByteString            -- ^ Encrypted data
createAndApply' g key src = do
  ng <- createGadget g
  initialize ng key
  unsafeTransformUnsafeGadget' ng src
    where
      createGadget :: (Gadget g) => g -> IO g
      createGadget _ = newGadget
{-# INLINEABLE createAndApply' #-}

-- | Returns the result of applying a gadget with the given iv on the
-- given bytestring.
applyGadget :: Gadget g
            => g
            -> Cxt (PrimitiveOf g)
            -> ByteString -- ^ Data
            -> ByteString -- ^ Output
applyGadget g k = unsafePerformIO . createAndApply' g k
{-# NOINLINE applyGadget #-}

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
