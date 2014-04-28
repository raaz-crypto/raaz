{- |

This module abstracts basic cryptographic primitive operations.

-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE KindSignatures   #-}
{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE CPP              #-}
module Raaz.Primitives.Mode
       ( Auth(..), authTag', verifyTag'
       , Sign(..)
       , Encrypt(..)
       , AuthEncrypt(..)
       ) where

import Control.Applicative
import System.IO.Unsafe    (unsafePerformIO)

import Raaz.Primitives
import Raaz.ByteSource
import Raaz.Serialize

-- | This class captures symmetric primitives which support generation
-- of authentication tags. The verification is done by generating the
-- authentication tag using the underlying gadget and then comparing
-- it with the given tag.
class ( Digestible prim
      , CryptoSerialize (Key prim)
      ) => Auth prim where
  -- | Get context from the Key.
  authCxt :: Key prim  -- ^ Auth Key
          -> Cxt prim  -- ^ Context

-- | Generate authentication tag.
authTag' :: ( PureByteSource src
            , Auth prim
            , PaddableGadget g
            , prim ~ PrimitiveOf g
            )
         => g             -- ^ Type of Gadget
         -> Key prim      -- ^ Key
         -> src           -- ^ Message
         -> Digest prim
authTag' g key src = unsafePerformIO $ withGadget (authCxt key) $ go g
  where go :: (Auth (PrimitiveOf g1), PaddableGadget g1)
            => g1 -> g1 -> IO (Digest (PrimitiveOf g1))
        go _ gad =  do
          transformGadget gad src
          toDigest <$> finalize gad

-- | Verify generated tag
verifyTag' :: ( PureByteSource src
              , Auth prim
              , PaddableGadget g
              , prim ~ PrimitiveOf g
              , Eq (Digest prim)
              )
           => g             -- ^ Type of Gadget
           -> Key prim      -- ^ Key
           -> src           -- ^ Message
           -> Digest prim
           -> Bool
verifyTag' g key src tag = authTag' g key src == tag


-- | This class captures primitives which support generation of
-- authenticated signatures and its verification. This is assymetric
-- version of `Auth`.
class ( Digestible (prim AuthMode)
      , Digestible (prim VerifyMode)
      , Digest (prim VerifyMode) ~ Bool
      , CryptoSerialize (Key (prim AuthMode))
      , CryptoSerialize (Key (prim VerifyMode))
      ) => Sign prim where
  -- | Get `AuthMode` context from the Key.
  signCxt :: Key (prim AuthMode) -- ^ Auth Key
          -> Cxt (prim AuthMode) -- ^ Context

  -- | Get `VerifyMode` context from Key and signature.
  verifyCxt :: Key (prim VerifyMode)  -- ^ Verify key
            -> Digest (prim AuthMode) -- ^ Signature
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
      ) => AuthEncrypt prim where
  -- | Get `AuthEncryptMode` context from key.
  authEncryptCxt :: Key (prim AuthEncryptMode) -- ^ Auth Encrypt key
                 -> Cxt (prim AuthEncryptMode) -- ^ Context

  -- | Get `VerifyDecryptMode` context from key.
  verifyDecryptCxt :: Key (prim VerifyDecryptMode) -- ^ Auth Decrypt key
                   -> Cxt (prim VerifyDecryptMode) -- ^ Context
