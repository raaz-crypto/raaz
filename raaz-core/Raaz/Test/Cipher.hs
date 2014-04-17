{-|

Generic tests for Hash implementations.

-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies     #-}

module Raaz.Test.Cipher
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

import           Raaz.ByteSource
import           Raaz.Types
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Util.ByteString           (base16)
import           Raaz.Serialize
import           Raaz.Test.Gadget


-- | Stansdard tests for ciphers
testStandardCiphers :: ( Gadget g
                       , Gadget g'
                       , HasName g
                       , HasName g'
                       , Encrypt p
                       , p EncryptMode ~ PrimitiveOf g
                       , p DecryptMode ~ PrimitiveOf g'
                       )
                    => g
                    -> g'
                    -> [(ByteString,ByteString,ByteString)] -- ^ (key, planetext, ciphertext)
                    -> Test
testStandardCiphers g g' vec = testGroup name [ unitTests g g' vec
                                              , encryptDecrypt g g' testiv
                                              ]
  where
    name = getName g ++ " && " ++ getName g'
    (testiv, _ , _) = head vec

-- | Checks standard plaintext - ciphertext for the given cipher
unitTests  :: ( Gadget g
              , Gadget g'
              , HasName g
              , HasName g'
              , Encrypt p
              , p EncryptMode ~ PrimitiveOf g
              , p DecryptMode ~ PrimitiveOf g'
              )
           => g
           -> g'
           -> [(ByteString,ByteString,ByteString)] -- ^ (key, planetext,ciphertest)
           -> Test

unitTests ge gd triples = testGroup "Unit tests" $ hUnitTestToTests $ test $ map checkCipher triples
  where label a = shorten (show $ base16 a)
        checkCipher (bk,a,b) =
          label a ~: test  ["Encryption" ~: (applyGadget ge ek a) ~?= b
                           ,"Decryption" ~: (applyGadget gd dk b) ~?= a]
          where
            ek = encryptCxt $ fromByteString bk
            dk = decryptCxt $ fromByteString bk

-- | Checks if decrypt . encrypt == id
encryptDecrypt :: ( Gadget g
                  , Gadget g'
                  , HasName g
                  , HasName g'
                  , Encrypt p
                  , p EncryptMode ~ PrimitiveOf g
                  , p DecryptMode ~ PrimitiveOf g'
                  )
               => g
               -> g'
               -> ByteString  -- ^ Context in ByteString
               -> Test
encryptDecrypt g g' bscxt = testInverse g g' (encryptCxt $ fromByteString bscxt)
                                             (decryptCxt $ fromByteString bscxt)

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
