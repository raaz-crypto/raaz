{-|

This module tests the endian explicit loads available at load.h
against the haskell variant.

-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Modules.C.Load
       ( tests
       ) where

import Control.Monad
import Data.Word
import Foreign.Storable
import Test.Framework(Test, testGroup)
import Test.Framework.Providers.QuickCheck2(testProperty)
import Test.QuickCheck
import Test.QuickCheck.Monadic(run, assert, monadicIO)

import Raaz.Test()
import Raaz.Core.Types
import Raaz.Util.Ptr

foreign import ccall unsafe
  "raaz/tests/platform/load_test.h raazTestsLoad32LE"
  c_get32le :: CryptoPtr -> Int -> IO Word32

foreign import ccall unsafe
  "raaz/tests/platform/load_test.h raazTestsLoad32BE"
  c_get32be :: CryptoPtr -> Int -> IO Word32

foreign import ccall unsafe
  "raaz/tests/platform/load_test.h raazTestsLoad64LE"
  c_get64le :: CryptoPtr -> Int -> IO Word64

foreign import ccall unsafe
  "raaz/tests/platform/load_test.h raazTestsLoad64BE"
  c_get64be :: CryptoPtr -> Int -> IO Word64


arraySize :: Int
arraySize = 42

-- | This is where the actual store/load is performed.
hStoreCLoad :: ( EndianStore b
               , Eq b
               , Num b
               , Integral a
               )
            => (CryptoPtr -> Int -> IO a) -- ^ The C loader function
            -> b                          -- ^ The value to test with
            -> IO Bool
hStoreCLoad loader b =  allocaBuffer sz runAll
  where sz = BYTES (sizeOf b * arraySize)
        runI cptr i = do _ <- storeAtIndex cptr i b
                         x <- fmap fromIntegral $ loader cptr i
                         return $ x == b
        runAll cptr = fmap and $ forM [0..arraySize - 1] $ runI cptr


-- | This is the property generator. The first value is an unused
-- value and is given to satisfy the typechecker.
prop_HStoreCLoad :: ( EndianStore b
                    , Num b
                    , Eq b
                    , Show b
                    , Integral a
                    )
                 => (CryptoPtr -> Int -> IO a) -- ^ The C loader function
                 -> b                          -- ^ dummy ignored
                 -> b                          -- ^ The value to test on
                 -> Property
prop_HStoreCLoad loader _ b = monadicIO $ do y <- run $ hStoreCLoad loader b
                                             assert y

tests :: Test
tests = testGroup "C Load:"
        [ testProperty "C load 32-bit LE"
            $ prop_HStoreCLoad c_get32le (undefined :: Word32LE)
        , testProperty "C load 32-bit BE"
            $ prop_HStoreCLoad c_get32be (undefined :: Word32BE)
        , testProperty "C load 64-bit LE"
            $ prop_HStoreCLoad c_get64le (undefined :: Word64LE)
        , testProperty "C load 64-bit BE"
            $ prop_HStoreCLoad c_get64be (undefined :: Word64BE)
        ]
