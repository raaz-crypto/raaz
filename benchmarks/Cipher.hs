{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances   #-}
{-# LANGUAGE CPP                 #-}
import           Control.Monad
import           Criterion
import           Criterion.Main
import           Criterion.Types
import           Foreign.Marshal.Alloc

import           Raaz.Core
import           Raaz.Cipher
import           Raaz.Cipher.Internal
import qualified Raaz.Cipher.ChaCha20.Implementation.CPortable as CPortable
# ifdef HAVE_VECTOR
import qualified Raaz.Cipher.ChaCha20.Implementation.GCCVector as GCCVector
# endif

-- | Buffer size used
bufSize :: BYTES Int
bufSize = 32 * 1024


main :: IO ()
main = allocaBytes (fromIntegral bufSize) $ \ ptr -> do
  defaultMain [ chacha20Bench ptr
              , aesBench ptr
              ]


----------------- Benchmarks of individual ciphers. ------------------------
aesBench :: Pointer -> Benchmark
aesBench ptr = bgroup "AES"
               [ benchCipher aes128cbc ptr
               , benchCipher aes192cbc ptr
               , benchCipher aes256cbc ptr
               ]

chacha20Bench :: Pointer -> Benchmark
chacha20Bench ptr = bgroup "ChaCha20"
                    [ benchEncrypt' chacha20 CPortable.implementation ptr
# ifdef HAVE_VECTOR
                    , benchEncrypt' chacha20 GCCVector.implementation ptr
# endif
                    ]


------------------ Low level functions ---------------------------------------
benchCipher :: (Cipher c, Recommendation c) => c -> Pointer -> Benchmark
benchCipher c ptr = bgroup (name c) [benchEncrypt c ptr, benchDecrypt c ptr]

benchEncrypt :: (Cipher c, Recommendation c) => c -> Pointer  -> Benchmark
benchEncrypt c = benchEncrypt' c $ recommended c

benchDecrypt  :: (Cipher c, Recommendation c) => c -> Pointer  -> Benchmark
benchDecrypt c = benchDecrypt' c $ recommended c


benchEncrypt' :: Cipher c => c -> Implementation c -> Pointer -> Benchmark
benchEncrypt' c si@(SomeCipherI imp) ptr = bench nm $ nfIO $ insecurely $ encryptBlocks imp ptr (atMost bufSize)
  where nm = "encrypt" ++ name si

benchDecrypt' :: Cipher c => c -> Implementation c -> Pointer -> Benchmark
benchDecrypt' c si@(SomeCipherI imp) ptr = bench nm $ nfIO $ insecurely $ decryptBlocks imp ptr (atMost bufSize)
  where nm = "decrypt" ++ name si
