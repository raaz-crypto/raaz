{- |

This module abstracts basic cryptographic primitive operations.

-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE KindSignatures   #-}
{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE CPP              #-}
module Raaz.Primitives.CryptoMode
       (
         -- * Cryptographic Modes
#if UseKinds
         CryptoMode(..)
#else
         AuthMode(..)
       , VerifyMode(..)
       , EncryptMode(..)
       , DecryptMode(..)
       , AuthEncryptMode(..)
       , VerifyDecryptMode(..)
#endif
       , Key
       , Auth(..), Encrypt(..), AuthEncrypt(..)
       ) where

import Raaz.Primitives
import Raaz.Serialize

-- | A primitive cryptographic operation consists of the following
--
-- * Generation of authenticated signature
--
-- * Verification of the signature against the message
--
-- * Encryption of a message
--
-- * Decryption of an encrypted message
--
-- * Authenticated encryption
--
-- * Decryption of message and verification of its signature
#if UseKinds
data CryptoMode = AuthMode
                | VerifyMode
                | EncryptMode
                | DecryptMode
                | AuthEncryptMode
                | VerifyDecryptMode
                deriving (Show, Eq)
#else
data AuthMode = AuthMode deriving (Show, Eq)

data VerifyMode = VerifyMode deriving (Show, Eq)

data EncryptMode = EncryptMode deriving (Show, Eq)

data DecryptMode = DecryptMode deriving (Show, Eq)

data AuthEncryptMode = AuthEncryptMode deriving (Show, Eq)

data VerifyDecryptMode = VerifyDecryptMode deriving (Show, Eq)

{-# DEPRECATED AuthMode, VerifyMode, EncryptMode, DecryptMode,
   AuthEncryptMode, VerifyDecryptMode
   "Will be changed to Data Constructor of type CryptoMode from ghc7.6 onwards" #-}
#endif

-- | Key required for a crypto primitive in particular mode.
#if UseKinds
type family Key (prim :: CryptoMode -> *) (mode :: CryptoMode) :: *
#else
type family Key (prim :: * -> *) mode :: *
#endif

-- | This class captures primitives which support generation of
-- authenticated signatures and its verification.
class ( Digestible (prim AuthMode)
      , Digestible (prim VerifyMode)
      , Digest (prim VerifyMode) ~ Bool
      , CryptoSerialize (Key prim AuthMode)
      , CryptoSerialize (Key prim VerifyMode)
      ) => Auth prim where
  -- | Get `AuthMode` context from the Key.
  authCxt :: Key prim AuthMode   -- ^ Auth Key
          -> Cxt (prim AuthMode) -- ^ Context

  -- | Get `VerifyMode` context from Key and signature.
  verifyCxt :: Key prim VerifyMode    -- ^ Verify key
            -> Digest (prim AuthMode) -- ^ Signature
            -> Cxt (prim VerifyMode)  -- ^ Context

-- | This class captures primitives which support encryption.
class ( CryptoSerialize (Key prim EncryptMode)
      , CryptoSerialize (Key prim DecryptMode)
      ) => Encrypt prim where
  -- | Get `EncryptMode` context from encryption key.
  encryptCxt :: Key prim EncryptMode   -- ^ Encrypt key
             -> Cxt (prim EncryptMode) -- ^ Context

  -- | Get `DecryptMode` context from decryption key.
  decryptCxt :: Key prim DecryptMode   -- ^ Decrypt key
             -> Cxt (prim DecryptMode) -- ^ Context

-- | This class captures primitives which support authenticated
-- encryption. A default `AuthEncrypt` instance can be provided
-- combining an `Auth` primitive and an `Encrypt` primitive.
class ( Digestible (prim AuthEncryptMode)
      , Digestible (prim VerifyDecryptMode)
      , Digest (prim AuthEncryptMode) ~ prim VerifyDecryptMode
      , Digest (prim VerifyDecryptMode) ~ Bool
      , CryptoSerialize (Key prim AuthEncryptMode)
      , CryptoSerialize (Key prim VerifyDecryptMode)
      ) => AuthEncrypt prim where
  -- | Get `AuthEncryptMode` context from key.
  authEncryptCxt :: Key prim AuthEncryptMode   -- ^ Auth Encrypt key
                 -> Cxt (prim AuthEncryptMode) -- ^ Context

  -- | Get `VerifyDecryptMode` context from key.
  verifyDecryptCxt :: Key prim VerifyDecryptMode   -- ^ Auth Decrypt key
                   -> Cxt (prim VerifyDecryptMode) -- ^ Context
