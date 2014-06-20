{- |

This module implements gadget instances for RSA signing and
verification.

-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE KindSignatures       #-}
{-# LANGUAGE CPP                  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module Raaz.RSA.Signature.Instances where

import Control.Applicative
import Data.Default
import Foreign.Storable

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Asymmetric
import Raaz.Core.Primitives.Hash

import Raaz.Number.Modular
import Raaz.Public
import Raaz.RSA.Types
import Raaz.RSA.Signature.Primitives

-------------------------------- PKCS Auth -------------------------------------


-- | Private Key is used for signature generation.
type instance Key (RSA k h PKCS SignMode) = PrivateKey k

-- | Primitive instance for Signature generation primitive.
instance Hash h => Primitive (RSA k h PKCS SignMode) where

  blockSize _ = blockSize (undefined :: h)

  data Cxt (RSA k h PKCS SignMode) = PKCSAuth (PrivateKey k) (Cxt h)

-- | Signature generation is a safe primitive if the underlying hash is safe.
instance Hash h => SafePrimitive (RSA k h PKCS SignMode)


instance ( Hash h
         , Storable k
         ) => CryptoPrimitive (RSA k h PKCS SignMode) where
  type Recommended (RSA k h PKCS SignMode) = RSAGadget k (Recommended h) PKCS SignMode
  type Reference (RSA k h PKCS SignMode) = RSAGadget k (Reference h) PKCS SignMode

-- | Return the signature as a Word. This is where the actual signing
-- is done of the calculated hash.
instance ( DEREncoding h
         , Modular k
         , Num k
         , Storable k
         , Eq k
         , Ord k
         , Hash h
         ) => Digestible (RSA k h PKCS SignMode) where

  type Digest (RSA k h PKCS SignMode) = RSA k h PKCS SignMode

  toDigest (PKCSAuth k hcxt) = RSA $ rsaPKCSSign (toDigest hcxt) k


-- | Padding for signature primitive is same as that of the underlying
-- hash.
instance Hash h => HasPadding (RSA k h PKCS SignMode) where
  padLength _  = padLength (undefined :: h)

  padding _ = padding (undefined :: h)

  unsafePad _ = unsafePad (undefined :: h)

  maxAdditionalBlocks _ = toEnum . fromEnum
                       $ maxAdditionalBlocks (undefined :: h)

-- | Gadget instance which is same as the underlying hashing gadget.
instance ( Gadget g
         , Hash (PrimitiveOf g)
         , PaddableGadget g
         , Storable k
         ) => Gadget (RSAGadget k g PKCS SignMode) where

  type PrimitiveOf (RSAGadget k g PKCS SignMode) = RSA k (PrimitiveOf g) PKCS SignMode

  type MemoryOf (RSAGadget k g PKCS SignMode) = (CryptoCell (PrivateKey k), MemoryOf g)

  newGadgetWithMemory (ck, gmem) = RSAGadget ck <$> newGadgetWithMemory gmem

  initialize (RSAGadget ck g) (PKCSAuth priv hcxt) =  cellStore ck priv
                                                   >> initialize g hcxt

  finalize (RSAGadget ck g) = PKCSAuth <$> cellLoad ck <*> finalize g

  apply (RSAGadget _ g) blks = apply g blks'
    where blks' = toEnum $ fromEnum blks


-- | PaddableGadget instance which is same as the underlying hashing
-- gadget.
instance ( Hash (PrimitiveOf g)
         , PaddableGadget g
         , Storable k
         ) => PaddableGadget (RSAGadget k g PKCS SignMode) where
  unsafeApplyLast (RSAGadget _ g) blks = unsafeApplyLast g blks'
    where blks' = toEnum $ fromEnum blks


--------------------------------- PKCS Verify ----------------------------------


-- | Public Key is use for signature verification
type instance Key (RSA k h PKCS VerifyMode) = PublicKey k

-- | Primitive instance for Signature verification primitive.
instance Hash h => Primitive (RSA k h PKCS VerifyMode) where

  blockSize _ = blockSize (undefined :: h)

  data Cxt (RSA k h PKCS VerifyMode) = PKCSVerify (PublicKey k) k (Cxt h)

-- | Signature verification is a safe primitive if the underlying hash is safe.
instance Hash h => SafePrimitive (RSA k h PKCS VerifyMode)


instance ( Hash h
         , Storable k
         ) => CryptoPrimitive (RSA k h PKCS VerifyMode) where
  type Recommended (RSA k h PKCS VerifyMode) = RSAGadget k (Recommended h) PKCS VerifyMode
  type Reference (RSA k h PKCS VerifyMode) = RSAGadget k (Reference h) PKCS VerifyMode

-- | Verify the signature and return `True` if success otherwise
-- `False`. This is where the actual signature verification is done of
-- the calculated hash.
instance ( DEREncoding h
         , Modular k
         , Num k
         , Storable k
         , Eq k
         , Ord k
         , Hash h
         ) => Digestible (RSA k h PKCS VerifyMode) where

  type Digest (RSA k h PKCS VerifyMode) = Bool

  toDigest (PKCSVerify k sig hcxt) = rsaPKCSVerify (toDigest hcxt) k sig

instance Hash h => HasPadding (RSA k h PKCS VerifyMode) where
  padLength _  = padLength (undefined :: h)

  padding _ = padding (undefined :: h)

  unsafePad _ = unsafePad (undefined :: h)

  maxAdditionalBlocks _ = toEnum . fromEnum
                       $ maxAdditionalBlocks (undefined :: h)

-- | Padding for verification primitive is same as that of the
-- underlying hash.
instance ( Gadget g
         , Hash (PrimitiveOf g)
         , PaddableGadget g
         , Storable k
         ) => Gadget (RSAGadget k g PKCS VerifyMode) where

  type PrimitiveOf (RSAGadget k g PKCS VerifyMode) = RSA k (PrimitiveOf g) PKCS VerifyMode

  type MemoryOf (RSAGadget k g PKCS VerifyMode) = ((CryptoCell (PublicKey k), CryptoCell k), MemoryOf g)

  newGadgetWithMemory (cell, gmem) = RSAGadget cell <$> newGadgetWithMemory gmem

  initialize (RSAGadget (ck, csig) g) (PKCSVerify pub sig hcxt) =  cellStore ck pub
                                                                >> cellStore csig sig
                                                                >> initialize g hcxt

  finalize (RSAGadget (ck, csig) g) = PKCSVerify <$> cellLoad ck <*> cellLoad csig<*> finalize g

  apply (RSAGadget _ g) blks = apply g blks'
    where blks' = toEnum $ fromEnum blks

-- | PaddableGadget gadget instance which is same as the underlying
-- hashing gadget.
instance ( Hash (PrimitiveOf g)
         , PaddableGadget g
         , Storable k
         ) => PaddableGadget (RSAGadget k g PKCS VerifyMode) where
  unsafeApplyLast (RSAGadget _ g) blks = unsafeApplyLast g blks'
    where blks' = toEnum $ fromEnum blks

------------------------------------- PKCS Auth instance ------------------------

-- | Auth instance for RSA PKCS signature scheme.
instance ( Modular k
         , Hash h
         , Storable k
         , Num k
         , Integral k
         , DEREncoding h
         ) => Sign (RSA k h PKCS) where
  signCxt priv = PKCSAuth priv def
  verifyCxt pub (RSA sig) = PKCSVerify pub sig def
