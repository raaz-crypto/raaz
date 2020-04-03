{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables      #-}
{-# LANGUAGE FlexibleContexts         #-}

{- HLINT ignore "Use camelCase" -}

-- | These tests compare the implementation of chacha20 of raaz and
-- that of monocypher. Raaz implements the ietf variants and hence
-- should be tested against crypto_ietf_chacha and not crypto_chacha C
-- function of Monocyper (>=3.0).
module Monocypher.ChaCha20Spec where


import qualified Data.ByteString as BS
import           Data.ByteString.Internal (unsafeCreate, createAndTrim')
import           Data.ByteString.Unsafe   (unsafeUseAsCStringLen)
import qualified Foreign.Storable as Storable
import           Foreign.Ptr
import           Foreign.C.Types
import           Foreign.C.String
import           Foreign.Marshal.Alloc
import           System.IO.Unsafe  (unsafePerformIO)

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
    crypto_unlock :: Ptr Word8 -- plain
                  -> Ptr Word8 -- key
                  -> Ptr Word8 -- nounce
                  -> Ptr Word8 -- mac
                  -> Ptr CChar -- cipher
                  -> Int       -- size
                  -> IO Int

foreign import ccall unsafe
   crypto_unlock_aead :: Ptr Word8 -- plain_text,
                      -> Ptr Word8 -- key
                      -> Ptr Word8 -- nounce
                      -> Ptr Word8 -- mac
                      -> Ptr CChar -- aad
                      -> Int       -- aad size
                      -> Ptr CChar -- cipher text
                      -> Int       -- cipher text size
                      -> IO Int
----------------------------------------------------------------------------------
call :: EndianStore a
     => a
     -> (Ptr b -> IO something)
     -> IO something
call a action =
  allocaBytes aSize $ \ aptr -> do store (castPtr aptr) a; action aptr
  where aSize = Storable.sizeOf (undefined `asTypeOf` a)

call2 :: (EndianStore a,  EndianStore b)
      => a
      -> b
      -> (Ptr a1 -> Ptr b1 -> IO something)
      -> IO something
call2 a b action = call a (call b . action)

------------------- Monocypher encryption -----------------------------------------

monocypher_chacha20_io :: Key ChaCha20
                       -> Nounce ChaCha20
                       -> Ptr Word8
                       -> CStringLen     -- plain text
                       -> IO ()
monocypher_chacha20_io k n cPtr (pPtr, l)
  = call k $ call n . crypto_ietf_chacha20 cPtr pPtr l

monocypher_xchacha20_io :: Key XChaCha20
                        -> Nounce XChaCha20
                        -> Ptr Word8
                        -> CStringLen     -- plain text
                        -> IO ()
monocypher_xchacha20_io k n cPtr (pPtr, l)
  = call k $ call n . crypto_xchacha20 cPtr pPtr l


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

-------------------- Monocypher encrypted auth ----------------------------------------

monocypher_unlock_aead_io :: ByteString    -- aad
                          -> ByteString    -- cipher text
                          -> Key XChaCha20
                          -> Nounce XChaCha20
                          -> Poly1305
                          -> Ptr Word8  -- Place to write the result.
                          -> IO (Int, Int, Bool)
monocypher_unlock_aead_io aad cText k n mac outPtr
  = let unlockAction kPtr nPtr mPtr
          = unsafeUseAsCStringLen aad
          $ \ (aadPtr, aadLen)     -> unsafeUseAsCStringLen cText
          $ \ (cTextPtr, cTextLen) ->
              do res <- crypto_unlock_aead outPtr kPtr nPtr mPtr aadPtr aadLen cTextPtr cTextLen
                 return (0, cTextLen, res == 0)
    in  call k $ call2 n mac . unlockAction


monocypher_unlock_io :: ByteString    -- cipher text
                     -> Key XChaCha20
                     -> Nounce XChaCha20
                     -> Poly1305
                     -> Ptr Word8  -- Place to write the result.
                     -> IO (Int, Int, Bool)
monocypher_unlock_io cText k n mac outPtr
  = let unlockAction kPtr nPtr mPtr
          = unsafeUseAsCStringLen cText
            $ \ (cTextPtr, cTextLen) ->
                do res <- crypto_unlock outPtr kPtr nPtr mPtr cTextPtr cTextLen
                   return (0, cTextLen, res == 0)
    in  call k $ call2 n mac . unlockAction


monocypher_unlock      :: Key XChaCha20
                       -> Nounce XChaCha20
                       -> XP.Locked ByteString
                       -> Maybe ByteString
monocypher_unlock k n locked =
  let cText = XP.unsafeToCipherText locked
      mac   = XP.unsafeToAuthTag locked
      len   = BS.length cText
  in unsafePerformIO $
     do (s, status) <- createAndTrim' len
                       $ monocypher_unlock_io cText k n mac
        if status then return (Just s) else return Nothing

monocypher_unlock_aead :: ByteString        -- aad
                       -> Key XChaCha20
                       -> Nounce XChaCha20
                       -> XP.AEAD ByteString ByteString
                       -> Maybe ByteString
monocypher_unlock_aead aad k n aead =
  let cText = XP.unsafeToCipherText aead
      mac   = XP.unsafeToAuthTag aead
      len   = BS.length cText
  in unsafePerformIO $
     do (s, status) <- createAndTrim' len
                       $ monocypher_unlock_aead_io aad cText k n mac
        if status then return (Just s) else return Nothing

spec :: Spec
spec = do
  describe "monocypher vs raaz" $ do

    prop "chacha20 encryption" $
      \ k n x ->  monocypher_chacha20_encrypt k n x `shouldBe` ChaCha20.encrypt k n x

    prop "xchacha20 encryption" $
      \ k n x -> monocypher_xchacha20_encrypt k n x `shouldBe` XChaCha20.encrypt k n x

    prop "raaz lock and monocypher unlock are inverses" $
      \ k n (x :: ByteString) -> monocypher_unlock k n (XP.lock k n x) `shouldBe` Just x

    prop "raaz lockWith vs monocypher unlockAead are inverses" $
      \ k n (aad :: ByteString) (x :: ByteString)
      -> monocypher_unlock_aead aad k n (XP.lockWith aad k n x) `shouldBe` Just x

  describe "raaz - lock/unlock are inverses" $ do

    prop "chacha20poly1305 " $
      \ k n (x :: ByteString) -> CP.unlock k n (CP.lock k n x) `shouldBe` Just x

    prop "xchacha20poly1305" $
      \ k n (x :: ByteString) -> XP.unlock k n (XP.lock k n x) `shouldBe` Just x

    prop "chacha20poly1305-aead" $
      \ k n (aad :: ByteString) (x :: ByteString)
      -> CP.unlockWith aad k n (CP.lockWith aad k n x) `shouldBe` Just x

    prop "xchacha20poly1305-aead" $
      \ k n (aad :: ByteString) (x :: ByteString)
      -> XP.unlockWith aad  k n (XP.lockWith aad k n x) `shouldBe` Just x
