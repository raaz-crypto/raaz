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
-- authenticated signatures and its verification. Note that the
-- `Digest` of authentication direction of the primitive is the
-- signature and is same as the primitive for the verification
-- direction.
class ( Digestible (prim AuthMode)
      , Digestible (prim VerifyMode)
      , Digest (prim AuthMode) ~ prim VerifyMode
      , Digest (prim VerifyMode) ~ Bool
      , CryptoSerialize (Key prim AuthMode)
      , CryptoSerialize (Key prim VerifyMode)
      ) => Auth prim where
  authCxt :: Key prim AuthMode-> Cxt (prim AuthMode)
  verifyCxt :: Key prim VerifyMode -> prim VerifyMode -> Cxt (prim VerifyMode)

-- | This class captures primitives which support encryption. Note
-- that the `ForwardKey` and `BackwardKey` might not be always same
-- (example, public key encryption).
class ( CryptoSerialize (Key prim EncryptMode)
      , CryptoSerialize (Key prim DecryptMode)
      ) => Encrypt prim where
  encryptCxt :: Key prim EncryptMode -> Cxt (prim EncryptMode)
  decryptCxt :: Key prim DecryptMode -> Cxt (prim DecryptMode)

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
  authEncryptCxt :: Key prim AuthEncryptMode -> Cxt (prim AuthEncryptMode)
  verifyDecryptCxt :: Key prim VerifyDecryptMode -> Cxt (prim VerifyDecryptMode)
