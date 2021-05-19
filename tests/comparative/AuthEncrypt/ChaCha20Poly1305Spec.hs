module AuthEncrypt.ChaCha20Poly1305Spec where

import           AuthEncrypt
import qualified AuthEncrypt.ChaCha20Poly1305.CPortable as CP
import qualified AuthEncrypt.ChaCha20Poly1305.CHandWritten as CH

spec :: Spec
spec = lockVsUnlock
       [ (CP.name, CP.unsafeLock), (CH.name, CH.unsafeLock) ]
       [ (CP.name, CP.unlock), (CH.name, CH.unlock) ]
