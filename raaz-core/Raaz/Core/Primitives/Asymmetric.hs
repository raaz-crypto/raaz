{- |

This module abstracts basic cryptographic primitive operations.

-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE KindSignatures   #-}
{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE CPP              #-}
module Raaz.Core.Primitives.Asymmetric
       ( Sign(..)
       , Encrypt(..)
       , SignEncrypt(..)
       ) where

import Control.Applicative
import System.IO.Unsafe    (unsafePerformIO)

import Raaz.Core.Primitives
import Raaz.Core.ByteSource
import Raaz.Serialize

-- | This class captures primitives which support generation of
-- authenticated signatures and its verification. This is assymetric
-- version of `Auth`.
class ( Digestible (prim SignMode)
      , Digestible (prim VerifyMode)
      , Digest (prim VerifyMode) ~ Bool
      , CryptoSerialize (Key (prim SignMode))
      , CryptoSerialize (Key (prim VerifyMode))
      ) => Sign prim where
  -- | Get `SignMode` context from the Key.
  signCxt :: Key (prim SignMode) -- ^ Auth Key
          -> Cxt (prim SignMode) -- ^ Context

  -- | Get `VerifyMode` context from Key and signature.
  verifyCxt :: Key (prim VerifyMode)  -- ^ Verify key
            -> Digest (prim SignMode) -- ^ Signature
            -> Cxt (prim VerifyMode)  -- ^ Context

-- | This class captures primitives which support encryption.
class ( CryptoSerialize (Key (prim EncryptMode))
      , CryptoSerialize (Key (prim DecryptMode))
      ) => Encrypt prim where
  -- | Get `EncryptMode` context from encryption key.
  encryptCxt :: Key (prim EncryptMode) -- ^ Encrypt key
             -> Cxt (prim EncryptMode) -- ^ Context

  -- | Get `DecryptMode` context from decryption key.
  decryptCxt :: Key (prim DecryptMode) -- ^ Decrypt key
             -> Cxt (prim DecryptMode) -- ^ Context

-- | This class captures primitives which support authenticated
-- encryption. A default `AuthEncrypt` instance can be provided
-- combining an `Auth` primitive and an `Encrypt` primitive.
class ( Digestible (prim AuthEncryptMode)
      , Digestible (prim VerifyDecryptMode)
      , Digest (prim AuthEncryptMode) ~ prim VerifyDecryptMode
      , Digest (prim VerifyDecryptMode) ~ Bool
      , CryptoSerialize (Key (prim AuthEncryptMode))
      , CryptoSerialize (Key (prim VerifyDecryptMode))
      ) => SignEncrypt prim where
  -- | Get `AuthEncryptMode` context from key.
  signEncryptCxt :: Key (prim AuthEncryptMode) -- ^ Auth Encrypt key
                 -> Cxt (prim AuthEncryptMode) -- ^ Context

  -- | Get `VerifyDecryptMode` context from key.
  verifyDecryptCxt :: Key (prim VerifyDecryptMode) -- ^ Auth Decrypt key
                   -> Cxt (prim VerifyDecryptMode) -- ^ Context
