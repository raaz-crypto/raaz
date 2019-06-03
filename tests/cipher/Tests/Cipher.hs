{-# LANGUAGE FlexibleContexts #-}
module Tests.Cipher( transform
                   , transformsTo
                   , keyStreamIs
                   , zeros
                   ) where

import           System.IO.Unsafe ( unsafePerformIO )
import           Raaz.Core
import           Prelude hiding (length)
import           Tests.Core.Imports
import           Tests.Core.Utils
import           Implementation
import qualified Utils as U

-- | Transforms the input byte string using the stream
-- cipher.
transform :: Key Prim     -- ^ The key for the stream cipher
          -> Nounce Prim  -- ^ The nounce used by the stream cipher.
          -> Counter Prim
          -> ByteString   -- ^ The bytestring to process
          -> ByteString
transform key nounce ctr bs = unsafePerformIO $ insecurely $ do
  initialise key
  initialise nounce
  initialise ctr
  U.transform bs

transformsTo :: (Format fmt1, Format fmt2)
             => fmt1
             -> fmt2
             -> (Key Prim, Nounce Prim, Counter Prim)
             -> Spec
transformsTo inp expected (key,nounce,ctr) = it msg $ result `shouldBe` decodeFormat expected
  where result = transform key nounce ctr $ decodeFormat inp
        msg  = unwords [ withKeyNounce key nounce ctr
                       , "encrypts"
                       , shortened $ show inp
                       , "to"
                       , shortened $ show expected
                       ]

withKeyNounce :: Key Prim
              -> Nounce Prim
              -> Counter Prim
              -> String
withKeyNounce key nounce ctr = unwords [ "with {"
                                       , "key:"    ++ shortened (show key)
                                       , ", nounce:" ++ shortened (show nounce)
                                       , ", counter:" ++ show (fromEnum ctr)
                                       , "}"
                                       ]

keyStreamIs :: Format fmt
            => fmt
            -> (Key Prim, Nounce Prim, Counter Prim)
            -> Spec
keyStreamIs expected (key, nounce, ctr) = it msg $ result `shouldBe` decoded
  where decoded = decodeFormat expected
        result = transform key nounce ctr $ zeros $ Raaz.Core.length decoded
        msg    = unwords [ withKeyNounce key nounce ctr
                         , "key stream is"
                         , shortened $ show expected
                         ]

zeros :: BYTES Int -> ByteString
zeros = toByteString . writeZero
  where writeZero :: LengthUnit u => u -> WriteIO
        writeZero = writeBytes 0
