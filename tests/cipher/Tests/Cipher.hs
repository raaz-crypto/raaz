{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MonoLocalBinds   #-}
module Tests.Cipher( transformsTo
                   , keyStreamIs
                   , zeros
                   ) where
import           Raaz.Core
import           Prelude hiding (length)
import           Tests.Core.Imports
import           Tests.Core.Utils
import           Implementation
import           Interface

transformsTo :: (Format fmt1, Format fmt2, Show (Nounce Prim), Show (Key Prim))
             => fmt1
             -> fmt2
             -> (Key Prim, Nounce Prim, Int)
             -> Spec
transformsTo inp expected (key,nounce,ctr) = it msg $ result `shouldBe` decodeFormat expected
  where result = encryptAt key nounce (blocksOf ctr Proxy) $ decodeFormat inp
        msg  = unwords [ withKeyNounce key nounce ctr
                       , "encrypts"
                       , shortened $ show inp
                       , "to"
                       , shortened $ show expected
                       ]

withKeyNounce :: (Show (Key Prim), Show (Nounce Prim))
              => Key Prim
              -> Nounce Prim
              -> Int
              -> String
withKeyNounce key nounce ctr = unwords [ "with {"
                                       , "key:"    ++ shortened (show key)
                                       , ", nounce:" ++ shortened (show nounce)
                                       , ", counter:" ++ show ctr
                                       , "}"
                                       ]

keyStreamIs :: ( Show (Key Prim), Show (Nounce Prim), Format fmt)
            => fmt
            -> (Key Prim, Nounce Prim, Int)
            -> Spec
keyStreamIs expected (key, nounce, ctr) = it msg $ result `shouldBe` decoded
  where decoded = decodeFormat expected
        result = encryptAt key nounce (blocksOf ctr Proxy) $ zeros $ Raaz.Core.length decoded
        msg    = unwords [ withKeyNounce key nounce ctr
                         , "key stream is"
                         , shortened $ show expected
                         ]

zeros :: BYTES Int -> ByteString
zeros = toByteString . writeZero
  where writeZero :: LengthUnit u => u -> WriteIO
        writeZero = writeBytes 0
