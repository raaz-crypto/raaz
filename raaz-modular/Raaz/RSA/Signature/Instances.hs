{- |

This module implements gadget instances for RSA signing and
verification.

-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE CPP                        #-}
{-# LANGUAGE UndecidableInstances       #-}
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
  type Recommended (RSA k h PKCS SignMode) = RSASignGadget k (Recommended h) PKCS SignMode
  type Reference (RSA k h PKCS SignMode) = RSASignGadget k (Reference h) PKCS SignMode

instance (Gadget g, Storable k, Hash (PrimitiveOf g)) => Memory (RSASignGadget k g n m) where

  memoryAlloc = RSASignGadget <$> memoryAlloc <*> memoryAlloc
  underlyingPtr (RSASignGadget kcell _) = underlyingPtr kcell

instance ( Storable k
         , Gadget g
         , Hash (PrimitiveOf g)
         , IV g ~ Key (PrimitiveOf g)
         ) => InitializableMemory (RSASignGadget k g n m) where
  type IV (RSASignGadget k g n m) = PrivateKey k

  initializeMemory rmem@(RSASignGadget kcell g) k = do
    cellPoke kcell k
    initializeMemory g (defaultKey $ primitiveOf (rHash rmem))
      where
        rHash :: RSASignGadget k g n m -> g
        rHash _ = undefined


-- | Return the signature as a Word. This is where the actual signing
-- is done of the calculated hash.
instance ( Gadget g
         , FinalizableMemory g
         , FV g ~ Key (PrimitiveOf g)
         , Hash (PrimitiveOf g)
         , Storable k
         , Modular k
         , DEREncoding (PrimitiveOf g)
         , Eq k
         , Ord k
         , Num k
         , IV g ~ Key (PrimitiveOf g)
         ) => FinalizableMemory (RSASignGadget k g n m) where
  type FV (RSASignGadget k g n m) = RSA k (PrimitiveOf g) PKCS SignMode

  finalizeMemory m@(RSASignGadget kcell g) = do
    k <- finalizeMemory kcell
    hcxt <- getDigest (getH m) <$> finalizeMemory g
    return $ RSA $ rsaPKCSSign hcxt k
    where
      getDigest :: g -> Key (PrimitiveOf g) -> (PrimitiveOf g)
      getDigest _ = hashDigest
      getH :: RSASignGadget k g n m -> g
      getH _ = undefined


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
         ) => Gadget (RSASignGadget k g PKCS SignMode) where

  type PrimitiveOf (RSASignGadget k g PKCS SignMode) = RSA k (PrimitiveOf g) PKCS SignMode

  apply (RSASignGadget _ g) blks                     = apply g blks'
    where blks'                                  = toEnum $ fromEnum blks

-- | PaddableGadget instance which is same as the underlying hashing
-- gadget.
instance ( Hash (PrimitiveOf g)
         , PaddableGadget g
         , Storable k
         ) => PaddableGadget (RSASignGadget k g PKCS SignMode) where
  unsafeApplyLast (RSASignGadget _ g) blks = unsafeApplyLast g blks'
    where blks' = toEnum $ fromEnum blks


-- --------------------------------- PKCS Verify ----------------------------------

-- -- | Primitive instance for Signature verification primitive.
instance Hash h => Primitive (RSA k h PKCS VerifyMode) where

  blockSize _ = blockSize (undefined :: h)

  type Key (RSA k h PKCS VerifyMode) = (PublicKey k, RSA k h PKCS SignMode)

-- -- | Signature verification is a safe primitive if the underlying hash is safe.
instance Hash h => SafePrimitive (RSA k h PKCS VerifyMode)


instance ( Hash h
         , Storable k
         ) => CryptoPrimitive (RSA k h PKCS VerifyMode) where
  type Recommended (RSA k h PKCS VerifyMode) = RSAVerifyGadget k (Recommended h) PKCS VerifyMode
  type Reference (RSA k h PKCS VerifyMode) = RSAVerifyGadget k (Reference h) PKCS VerifyMode


instance (Gadget g, Storable k, Hash (PrimitiveOf g)) => Memory (RSAVerifyGadget k g n m) where

  memoryAlloc = RSAVerifyGadget <$> memoryAlloc <*> memoryAlloc
  underlyingPtr (RSAVerifyGadget cellTuple _) = underlyingPtr cellTuple

instance ( Storable k
         , Gadget g
         , Hash (PrimitiveOf g)
         , IV g ~ Key (PrimitiveOf g)
         ) => InitializableMemory (RSAVerifyGadget k g n m) where
  type IV (RSAVerifyGadget k g n m) = (PublicKey k, RSA k (PrimitiveOf g) PKCS SignMode)

  initializeMemory rmem@(RSAVerifyGadget (kcell, sigcell) g) (k, RSA sig) = do
    cellPoke kcell k
    cellPoke sigcell sig
    initializeMemory g (defaultKey $ primitiveOf (rHash rmem))
      where
        rHash :: RSAVerifyGadget k g n m -> g
        rHash _ = undefined

-- | Verify the signature and return `True` if success otherwise
-- `False`. This is where the actual signature verification is done of
-- the calculated hash.
instance ( Gadget g
         , FinalizableMemory g
         , FV g ~ Key (PrimitiveOf g)
         , Hash (PrimitiveOf g)
         , Storable k
         , Modular k
         , DEREncoding (PrimitiveOf g)
         , Eq k
         , Ord k
         , Num k
         ) => FinalizableMemory (RSAVerifyGadget k g n m) where
  type FV (RSAVerifyGadget k g n m) = Bool

  finalizeMemory m@(RSAVerifyGadget (kcell, sigcell) g) = do
    k <- finalizeMemory kcell
    sig <- finalizeMemory sigcell
    hcxt <- getDigest (getH m) <$> finalizeMemory g
    return $ rsaPKCSVerify hcxt k sig
    where
      getDigest :: g -> Key (PrimitiveOf g) -> (PrimitiveOf g)
      getDigest _ = hashDigest
      getH :: RSAVerifyGadget k g n m -> g
      getH _ = undefined

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
         ) => Gadget (RSAVerifyGadget k g PKCS VerifyMode) where

  type PrimitiveOf (RSAVerifyGadget k g PKCS VerifyMode)     = RSA k (PrimitiveOf g) PKCS VerifyMode

  apply (RSAVerifyGadget _ g) blks                           = apply g blks'
    where blks'                                        = toEnum $ fromEnum blks

-- | PaddableGadget gadget instance which is same as the underlying
-- hashing gadget.
instance ( Hash (PrimitiveOf g)
         , PaddableGadget g
         , Storable k
         ) => PaddableGadget (RSAVerifyGadget k g PKCS VerifyMode) where
  unsafeApplyLast (RSAVerifyGadget _ g) blks = unsafeApplyLast g blks'
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
