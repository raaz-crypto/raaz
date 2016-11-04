{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances   #-}
import           Control.Monad
import           Criterion
import           Criterion.Main
import           Criterion.Types
import           Foreign.Marshal.Alloc

import           Raaz.Core
import           Raaz.Cipher
import           Raaz.Cipher.Internal
import qualified Raaz.Cipher.ChaCha20.Implementation.CPortable as CPortable
import qualified Raaz.Cipher.ChaCha20.Implementation.GCCVector as GCCVector


main :: IO ()
main = allocaBytes (fromIntegral bufSize) $ \ ptr -> do
  defaultMain
    [ bgroup "ciphers"
      [ benchCipher aes128cbc ptr
      , benchCipher aes192cbc ptr
      , benchCipher aes256cbc ptr
      ]
    , bgroup "chacha20 implementations"
      [ benchEncrypt' chacha20 CPortable.implementation ptr
      , benchEncrypt' chacha20 GCCVector.implementation ptr
      ]
    ]

bufSize :: BYTES Int
bufSize = 32 * 1024


benchCipher :: (Cipher c, Recommendation c)
                => c -> Pointer -> Benchmark
benchCipher c ptr = bgroup (name c) [benchEncrypt c ptr, benchDecrypt c ptr]


benchEncrypt :: (Cipher c, Recommendation c)
              => c -> Pointer  -> Benchmark
benchEncrypt c = benchEncrypt' c $ recommended c


benchEncrypt' :: Cipher c
               => c
               -> Implementation c
               -> Pointer -> Benchmark
benchEncrypt' c si@(SomeCipherI imp) ptr = bench nm $ nfIO $ insecurely $ encryptBlocks imp ptr (atMost bufSize)
  where nm = "encrypt" ++ name si


benchDecrypt  :: (Cipher c, Recommendation c)
              => c -> Pointer  -> Benchmark
benchDecrypt c = benchDecrypt' c $ recommended c

benchDecrypt' :: Cipher c
               => c
               -> Implementation c
               -> Pointer -> Benchmark
benchDecrypt' c si@(SomeCipherI imp) ptr = bench nm $ nfIO $ insecurely $ decryptBlocks imp ptr (atMost bufSize)
  where nm = "decrypt" ++ name si
