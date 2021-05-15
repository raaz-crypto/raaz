module Encrypt.ChaCha20Spec where

import           Encrypt
import qualified Encrypt.ChaCha20.CPortable    as CP
import qualified Encrypt.ChaCha20.CHandWritten as CH

spec :: Spec
spec = do
  describe "encryption" $ encryptSpec  [ (CP.name, CP.encrypt)
                                       , (CH.name, CH.encrypt)
                                       ]
  describe "decryption" $ decryptSpec  [ (CP.name, CP.decrypt)
                                       , (CH.name, CH.decrypt)
                                       ]
