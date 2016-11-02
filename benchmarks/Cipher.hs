{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances   #-}
import           Control.Monad
import           Criterion
import           Criterion.Main
import           Foreign.Marshal.Alloc

import           Raaz.Core
import           Raaz.Cipher
import           Raaz.Cipher.Internal

main :: IO ()
main = allocaBytes (fromIntegral bufSize) $ \ ptr -> do
  defaultMain
    [ bgroup "ciphers"
      [ bench "aes128cbc encrypt"   $ nfIO $ aes128cbcEncrypt ptr
      , bench "aes128cbc decrypt"   $ nfIO $ aes128cbcDecrypt ptr
      , bench "chacha20 transform"  $ nfIO $ chacha20Transform ptr
      ]
    ]

bufSize :: BYTES Int
bufSize = 32 * 1024

aes128cbcEncrypt :: Pointer  ->  IO ()
aes128cbcEncrypt buf =  (\ (SomeCipherI imp) -> insecurely $ encryptBlocks imp buf (atMost bufSize))
                        $ recommended aes128cbc

aes128cbcDecrypt :: Pointer  ->  IO ()
aes128cbcDecrypt buf =  (\ (SomeCipherI imp) -> insecurely $ decryptBlocks imp buf (atMost bufSize))
                        $ recommended aes128cbc

chacha20Transform :: Pointer -> IO ()
chacha20Transform buf = (\ (SomeCipherI imp) -> insecurely $ encryptBlocks imp buf (atMost bufSize))
                        $ recommended chacha20
