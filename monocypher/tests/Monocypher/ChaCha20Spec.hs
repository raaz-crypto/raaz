{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables      #-}
{-# LANGUAGE FlexibleContexts         #-}
-- | These tests compare the implementation of chacha20 of raaz and
-- that of monocypher. The only challenge here is to adjust the nounce
-- as raaz implements the ieft variants where as monocypher implements
-- the djb variant. The tests therefore works only for nounces that
-- are 64-bit wide.
module Monocypher.ChaCha20Spec where


import qualified Data.ByteString as BS
import           Data.ByteString.Internal (unsafeCreate)
import           Data.ByteString.Unsafe   (unsafeUseAsCStringLen)
import qualified Foreign.Storable as Storable
import           Foreign.Ptr
import           Foreign.C.Types
import           Foreign.C.String
import           Foreign.Marshal.Alloc

import           Raaz.Core
import qualified Raaz.Encrypt.ChaCha20  as ChaCha20
import qualified Raaz.Encrypt.XChaCha20 as XChaCha20
import qualified Raaz.AuthEncrypt.ChaCha20Poly1305  as CP
import qualified Raaz.AuthEncrypt.XChaCha20Poly1305 as XP

import           Tests.Core

foreign import ccall unsafe
      crypto_ietf_chacha20 :: Ptr Word8  -- cipher text
                           -> Ptr CChar  -- plain text
                           -> Int        -- Size
                           -> Ptr Word8  -- key
                           -> Ptr Word8  -- nounce
                           -> IO ()

foreign import ccall unsafe
    crypto_xchacha20 :: Ptr Word8  -- cipher text
                     -> Ptr CChar  -- plain text
                     -> Int        -- Size
                     -> Ptr Word8  -- key
                     -> Ptr Word8  -- nounce
                     -> IO ()

foreign import ccall unsafe
    crypto_lock :: Ptr Word8  -- mac
                -> Ptr Word8  -- cipher_text,
                -> Ptr Word8  -- key
                -> Ptr Word8  -- nonce
                -> Ptr CChar  -- plain_text
                -> Int        -- text_size
                -> IO ()

foreign import ccall unsafe
    crypto_unlock :: Ptr Word8 -- plain
                  -> Ptr Word8 -- key
                  -> Ptr Word8 -- nounce
                  -> Ptr Word8 -- mac
                  -> Ptr Word8 -- cipher
                  -> Int       -- size
                  -> IO Int

foreign import ccall unsafe
   crypto_lock_aead :: Ptr Word8 -- mac
                    -> Ptr Word8 -- cipher text
                    -> Ptr Word8 -- key
                    -> Ptr Word8 -- nonce
                    -> Ptr Word8 -- AAD
                    -> Int       -- aad size
                    -> Ptr CChar -- plain text
                    -> Int       -- text size
                    -> IO ()

foreign import ccall unsafe
   crypto_unlock_aead :: Ptr Word8 -- plain_text,
                      -> Ptr Word8 -- key
                      -> Ptr Word8 -- nounce
                      -> Ptr Word8 -- mac
                      -> Ptr Word8 -- aad
                      -> Int       -- aad size
                      -> Ptr Word8 -- cipher text
                      -> Int       -- cipher text size
                      -> IO Int
----------------------------------------------------------------------------------

withKN :: (EndianStore (Key prim), EndianStore (Nounce prim))
       => Key prim
       -> Nounce prim
       -> (Ptr Word8 -> Ptr Word8 -> IO a)
       -> IO a
withKN k n action
  = allocaBytes kSize
    $ \ kptr ->
        allocaBytes nSize
        $ \ nptr ->
            do store (castPtr kptr) k
               store (castPtr nptr) n
               action kptr nptr
  where kSize = Storable.sizeOf (undefined :: Key ChaCha20)
        nSize = Storable.sizeOf (undefined :: Nounce ChaCha20)

monocypher_chacha20_io :: Key ChaCha20
                       -> Nounce ChaCha20
                       -> Ptr Word8
                       -> CStringLen     -- plain text
                       -> IO ()
monocypher_chacha20_io k n cPtr (pPtr, l)
  = withKN k n $ crypto_ietf_chacha20 cPtr pPtr l

monocypher_xchacha20_io :: Key XChaCha20
                        -> Nounce XChaCha20
                        -> Ptr Word8
                        -> CStringLen     -- plain text
                        -> IO ()
monocypher_xchacha20_io k n cPtr (pPtr, l)
  = withKN k n $ crypto_xchacha20 cPtr pPtr l

monocypher_chacha20_encrypt :: Key ChaCha20
                            -> Nounce ChaCha20
                            -> ByteString
                            -> ByteString
monocypher_chacha20_encrypt k n bs = unsafeFromByteString $ unsafeCreate l creator
  where l = BS.length bs
        creator = unsafeUseAsCStringLen bs . monocypher_chacha20_io k n


monocypher_xchacha20_encrypt :: Key XChaCha20
                             -> Nounce XChaCha20
                             -> ByteString
                             -> ByteString
monocypher_xchacha20_encrypt k n bs = unsafeFromByteString $ unsafeCreate l creator
  where l = BS.length bs
        creator = unsafeUseAsCStringLen bs . monocypher_xchacha20_io k n

spec :: Spec
spec = do prop "monocypher vs raaz - chacha20" $
            \ k n x ->  monocypher_chacha20_encrypt k n x `shouldBe` ChaCha20.encrypt k n x

          prop "monocypher vs raaz - xchacha20" $
            \ k n x -> monocypher_xchacha20_encrypt k n x `shouldBe` XChaCha20.encrypt k n x

          prop "raaz chacha20poly1305 - lock/unlock are inverse" $
            \ k n (x :: ByteString) -> CP.unlock k n (CP.lock k n x) `shouldBe` Just x

          prop "raaz xchacha20poly1305 - lock/unlock are inverse" $
            \ k n (x :: ByteString) -> XP.unlock k n (XP.lock k n x) `shouldBe` Just x


          prop "raaz chacha20poly1305 AEAD - lock/unlock are inverse" $
            \ k n (aad :: ByteString) (x :: ByteString)
            -> CP.unlockWith aad k n (CP.lockWith aad k n x) `shouldBe` Just x

          prop "raaz xchacha20poly1305 AEAD - lock/unlock are inverse" $
            \ k n (aad :: ByteString) (x :: ByteString)
            -> XP.unlockWith aad  k n (XP.lockWith aad k n x) `shouldBe` Just x
