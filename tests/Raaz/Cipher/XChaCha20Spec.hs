{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE DataKinds            #-}

module Raaz.Cipher.XChaCha20Spec where

import           Tests.Core
import qualified XChaCha20.Implementation as XI
import qualified ChaCha20.CPortable as CP
import           System.IO.Unsafe( unsafePerformIO )


unsafeRun :: Memory mem => (mem -> IO a) -> a
unsafeRun = unsafePerformIO . withMemory

setup :: Key ChaCha20
      -> Nounce XChaCha20
      -> (Key ChaCha20, Nounce ChaCha20)
setup k n = unsafeRun setupMem
  where setupMem :: CP.Internals -> IO (Key ChaCha20, Nounce ChaCha20)
        setupMem mem = do initialise k mem
                          CP.xchacha20Setup n mem
                          (,) <$> extract (keyCell mem)
                              <*> extract (ivCell mem)
xinit :: Key XChaCha20
      -> Nounce XChaCha20
      -> (Key ChaCha20, Nounce ChaCha20)
xinit k n = unsafeRun xinitMem
  where xinitMem :: XI.Internals -> IO (Key ChaCha20, Nounce ChaCha20)
        xinitMem mem = do initialise k mem
                          initialise n mem
                          (,) <$> extract (keyCell $ XI.chacha20Internals mem)
                              <*> extract (ivCell  $ XI.chacha20Internals mem)

mesg :: (Show k, Show n, Show kp, Show iv)
     => k -> n -> kp -> iv -> String
mesg k n kp iv = unwords ["for key:"
                         , shortened $ show k
                         , "and nounce:"
                         , shortened $ show n
                         , "the key should be"
                         , shortened $ show kp
                         , "and the internal nounce should be"
                         , show iv
                         ]

setupSpec :: Key ChaCha20  -> Nounce XChaCha20 -> (Key ChaCha20, Nounce ChaCha20) -> Spec
setupSpec k n (kp,iv) = it msg $ setup k n `shouldBe` (kp,iv)
  where msg = unwords ["setup:", mesg k n kp iv]

xinitSpec :: Key XChaCha20 -> Nounce XChaCha20 -> (Key ChaCha20,Nounce ChaCha20) -> Spec
xinitSpec k n (kp,iv)  = it msg $ xinit k n `shouldBe` (kp,iv)
  where msg = unwords ["xinit:", mesg k n kp iv]

spec :: Spec
spec = do
  setupSpec
    "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
    "00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27:00:01:02:03:04:05:06:07"
    ("82413b42 27b27bfe d30e4250 8a877d73 a0f9e4d5 8a74a853 c12ec413 26d3ecdc", "00:00:00:00:00:01:02:03:04:05:06:07")

  xinitSpec
    "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
    "00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27:00:01:02:03:04:05:06:07"
    ("82413b42 27b27bfe d30e4250 8a877d73 a0f9e4d5 8a74a853 c12ec413 26d3ecdc", "00:00:00:00:00:01:02:03:04:05:06:07")
