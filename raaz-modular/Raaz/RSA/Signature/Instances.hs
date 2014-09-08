{- |

This module implements gadget instances for RSA signing and
verification.

-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE CPP                        #-}
{-# OPTIONS_GHC -fno-warn-orphans       #-}
module Raaz.RSA.Signature.Instances () where

import Control.Applicative
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


-- | Primitive instance for Signature generation primitive.
instance Hash h => Primitive (RSA k h PKCS SignMode) where

  blockSize _ = blockSize (undefined :: h)

  type Key (RSA k h PKCS SignMode) = PrivateKey k

-- | Signature generation is a safe primitive if the underlying hash is safe.
instance Hash h => SafePrimitive (RSA k h PKCS SignMode)


instance ( Hash h
         , Storable k
         ) => CryptoPrimitive (RSA k h PKCS SignMode) where
  type Recommended (RSA k h PKCS SignMode) = RSAGadget k (Recommended h) PKCS SignMode
  type Reference (RSA k h PKCS SignMode) = RSAGadget k (Reference h) PKCS SignMode


-- | Memory used in RSA Signing gadget
newtype RSASignMem k h m = RSASignMem (CryptoCell (PrivateKey k), m)

deriving instance (Storable k, Memory m) => Memory (RSASignMem k h m)

instance ( Storable k
         , InitializableMemory m
         , Hash h
         , IV m ~ Key h
         ) => InitializableMemory (RSASignMem k h m) where
  type IV (RSASignMem k h m) = PrivateKey k

  initializeMemory rmem@(RSASignMem (kcell, hmem)) k = do
    cellPoke kcell k
    initializeMemory hmem (defaultCxt (rHash rmem))
      where
        rHash :: RSASignMem k h m -> h
        rHash _ = undefined


-- | Return the signature as a Word. This is where the actual signing
-- is done of the calculated hash.
instance ( FinalizableMemory m
         , FV m ~ Key h
         , Hash h
         , Storable k
         , Modular k
         , DEREncoding h
         , Eq k
         , Ord k
         , Num k
         ) => FinalizableMemory (RSASignMem k h m) where
  type FV (RSASignMem k h m) = RSA k h PKCS SignMode

  finalizeMemory m@(RSASignMem (kcell, hmem)) = do
    k <- finalizeMemory kcell
    hcxt <- getDigest (getH m) <$> finalizeMemory hmem
    return $ RSA $ rsaPKCSSign hcxt k
    where
      getDigest :: h -> Key h -> h
      getDigest _ = hashDigest
      getH :: RSASignMem k h m -> h
      getH = undefined


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

  type MemoryOf (RSAGadget k g PKCS SignMode)    = RSASignMem k (PrimitiveOf g) (MemoryOf g)

  newGadgetWithMemory (RSASignMem (ck, gmem))    = RSAGadget ck <$> newGadgetWithMemory gmem

  getMemory (RSAGadget ck g)                     = RSASignMem (ck, getMemory g)

  apply (RSAGadget _ g) blks                     = apply g blks'
    where blks'                                  = toEnum $ fromEnum blks


-- | PaddableGadget instance which is same as the underlying hashing
-- gadget.
instance ( Hash (PrimitiveOf g)
         , PaddableGadget g
         , Storable k
         ) => PaddableGadget (RSAGadget k g PKCS SignMode) where
  unsafeApplyLast (RSAGadget _ g) blks = unsafeApplyLast g blks'
    where blks' = toEnum $ fromEnum blks


--------------------------------- PKCS Verify ----------------------------------

-- | Primitive instance for Signature verification primitive.
instance Hash h => Primitive (RSA k h PKCS VerifyMode) where

  blockSize _ = blockSize (undefined :: h)

  type Key (RSA k h PKCS VerifyMode) = (PublicKey k, RSA k h PKCS SignMode)

-- | Signature verification is a safe primitive if the underlying hash is safe.
instance Hash h => SafePrimitive (RSA k h PKCS VerifyMode)


instance ( Hash h
         , Storable k
         ) => CryptoPrimitive (RSA k h PKCS VerifyMode) where
  type Recommended (RSA k h PKCS VerifyMode) = RSAGadget k (Recommended h) PKCS VerifyMode
  type Reference (RSA k h PKCS VerifyMode) = RSAGadget k (Reference h) PKCS VerifyMode


-- | Memory used in RSA Verification gadget
newtype RSAVerifyMem k h m = RSAVerifyMem (CryptoCell (PublicKey k), CryptoCell k, m)

deriving instance (Storable k, Memory m) => Memory (RSAVerifyMem k h m)

instance ( Storable k
         , InitializableMemory m
         , Hash h
         , IV m ~ Key h
         ) => InitializableMemory (RSAVerifyMem k h m) where
  type IV (RSAVerifyMem k h m) = (PublicKey k, RSA k h PKCS SignMode)

  initializeMemory rmem@(RSAVerifyMem (kcell, sigcell, hmem)) (k, RSA sig) = do
    cellPoke kcell k
    cellPoke sigcell sig
    initializeMemory hmem (defaultCxt (rHash rmem))
      where
        rHash :: RSAVerifyMem k h m -> h
        rHash _ = undefined

-- | Verify the signature and return `True` if success otherwise
-- `False`. This is where the actual signature verification is done of
-- the calculated hash.
instance ( FinalizableMemory m
         , FV m ~ Key h
         , Hash h
         , Storable k
         , Modular k
         , DEREncoding h
         , Eq k
         , Ord k
         , Num k
         ) => FinalizableMemory (RSAVerifyMem k h m) where
  type FV (RSAVerifyMem k h m) = Bool

  finalizeMemory m@(RSAVerifyMem (kcell, sigcell, hmem)) = do
    k <- finalizeMemory kcell
    sig <- finalizeMemory sigcell
    hcxt <- getDigest (getH m) <$> finalizeMemory hmem
    return $ rsaPKCSVerify hcxt k sig
    where
      getDigest :: h -> Key h -> h
      getDigest _ = hashDigest
      getH :: RSAVerifyMem k h m -> h
      getH = undefined

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

  type PrimitiveOf (RSAGadget k g PKCS VerifyMode)     = RSA k (PrimitiveOf g) PKCS VerifyMode

  type MemoryOf (RSAGadget k g PKCS VerifyMode)        = RSAVerifyMem k (PrimitiveOf g) (MemoryOf g)

  newGadgetWithMemory (RSAVerifyMem (cpk, csig, gmem)) = RSAGadget (cpk,csig) <$> newGadgetWithMemory gmem

  getMemory (RSAGadget (ck,csig) g)                    = RSAVerifyMem (ck, csig, getMemory g)

  apply (RSAGadget _ g) blks                           = apply g blks'
    where blks'                                        = toEnum $ fromEnum blks

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
         ) => Sign (RSA k h PKCS)

-- | Satisfy some types.
getHash :: RSA k h PKCS SignMode -> h
getHash = undefined
