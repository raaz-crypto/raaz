{-# LANGUAGE FlexibleContexts #-}
module Tests.Cipher( transform
                   , transformsTo
                   , keyStreamIs
                   , zeros
                   ) where

import           System.IO.Unsafe ( unsafePerformIO )

import           Tests.Core.Imports
import           Tests.Core.Utils
import           Implementation
import qualified Utils as U

-- | Transforms the input byte string using the stream
-- cipher.
transform :: Key Prim     -- ^ The key for the stream cipher
          -> ByteString   -- ^ The bytestring to process
          -> ByteString
transform key bs = unsafePerformIO $ insecurely $ do
  initialise key
  U.transform bs

transformsTo :: (Format fmt1, Format fmt2)
              => (Key Prim -> String)
              -> fmt1
              -> fmt2
              -> Key Prim
              -> Spec
transformsTo kprint inp expected key = it msg $ result `shouldBe` decodeFormat expected
  where result = transform key $ decodeFormat inp
        msg  = unwords [ "with key", kprint key
                       , "encrypts"
                       , shortened $ show inp
                       , "to"
                       , shortened $ show expected
                       ]

keyStreamIs :: Format fmt
            => (Key Prim -> String)
            -> fmt
            -> Key Prim
            -> Spec
keyStreamIs kprint expected key = it msg $ result `shouldBe` decodeFormat expected
  where result = transform key $ zeros (1 `blocksOf` Proxy)
        msg    = unwords ["with key", kprint key
                         , "key stream is"
                         , shortened $ show expected
                         ]

zeros :: BLOCKS Prim -> ByteString
zeros = toByteString . writeZero
  where writeZero :: LengthUnit u => u -> WriteIO
        writeZero = writeBytes 0
