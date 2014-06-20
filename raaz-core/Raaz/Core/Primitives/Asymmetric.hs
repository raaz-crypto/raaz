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
       , sign, sign', verify, verify'
       ) where

import Control.Applicative
import System.IO.Unsafe

import Raaz.Core.Primitives
import Raaz.Core.ByteSource
import Raaz.Core.Serialize

-- | This class captures primitives which support generation of
-- authenticated signatures and its verification. This is assymetric
-- version of `Auth`.
class ( Digestible (prim SignMode)
      , Digestible (prim VerifyMode)
      , Digest (prim VerifyMode) ~ Bool
      , Digest (prim SignMode) ~ prim SignMode
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


-- | Generate Signature.
sign' :: ( PureByteSource src
         , Sign p
         , prim ~ p SignMode
         , PaddableGadget g
         , prim ~ PrimitiveOf g
         )
      => g             -- ^ Type of Gadget
      -> Key prim      -- ^ Key
      -> src           -- ^ Message
      -> prim
sign' g key src = unsafePerformIO $ withGadget (signCxt key) $ go g
  where go :: (Sign prim, PaddableGadget g1, prim SignMode ~ PrimitiveOf g1)
           => g1 -> g1 -> IO (Digest (PrimitiveOf g1))
        go _ gad =  do
          transformGadget gad src
          toDigest <$> finalize gad

-- | Generate signature using recommended gadget.
sign :: ( PureByteSource src
        , Sign p
        , prim ~ p SignMode
        , PaddableGadget (Recommended prim)
        , CryptoPrimitive prim
        )
        => Key prim      -- ^ Key
        -> src           -- ^ Message
        -> prim
sign key src = sig
  where
    sig = sign' (recommended sig) key src
    recommended :: prim -> Recommended prim
    recommended _ = undefined

-- | Verify Signature.
verify' :: ( PureByteSource src
           , Sign p
           , prim ~ p VerifyMode
           , PaddableGadget g
           , prim ~ PrimitiveOf g
           )
           => g             -- ^ Type of Gadget
           -> Key prim      -- ^ Key
           -> src           -- ^ Message
           -> p SignMode
           -> Bool
verify' g key src p  = unsafePerformIO $ withGadget (verifyCxt key p) $ go g
  where go :: (Sign prim, PaddableGadget g1, prim VerifyMode ~ PrimitiveOf g1)
           => g1 -> g1 -> IO (Digest (PrimitiveOf g1))
        go _ gad =  do
          transformGadget gad src
          toDigest <$> finalize gad

-- | Verify tag using recommended gadget.
verify :: ( PureByteSource src
          , Sign p
          , prim ~ p VerifyMode
          , PaddableGadget (Recommended prim)
          , CryptoPrimitive prim
          , prim ~ PrimitiveOf (Recommended prim)
          )
          => Key prim      -- ^ Key
          -> src           -- ^ Message
          -> p SignMode
          -> Bool
verify key src prim = verify' (recommended prim) key src prim
  where
    recommended :: p SignMode -> Recommended (p VerifyMode)
    recommended _ = undefined

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
