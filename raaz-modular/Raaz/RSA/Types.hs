{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE CPP                        #-}
module Raaz.RSA.Types
       ( PublicKey (..)
       , PrivateKey (..)
       , MGF
       , keySize, xorByteString
       , RSA(..)
#if UseKinds
       , RSAMode(..)
#else
       , PKCS(..)
       , PSS(..)
       , OAEP(..)
#endif
       , RSAGadget(..)
       ) where

import Control.Applicative
import Data.Bits
import Data.ByteString       as BS
import Data.Monoid
import Foreign.Ptr           (castPtr)
import Foreign.Storable      (Storable(..), sizeOf)

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Parse.Unsafe
import Raaz.Core.Write.Unsafe
import Raaz.Core.Serialize
import Raaz.Core.Types

import Raaz.Number.Internals
import Raaz.Number.Util

-- | RSA Public Key
data PublicKey w = PublicKey
                   { pubN    :: w           -- ^ n
                   , pubE    :: w           -- ^ e
                   } deriving Show

-- | RSA Private Key
data PrivateKey w = PrivateKey
                    { privN    :: w           -- ^ Modulus n
                    , privE    :: w           -- ^ Exponent e
                    , privD    :: w           -- ^ Exponent d
                    , privP    :: w           -- ^ p prime number
                    , privQ    :: w           -- ^ q prime number
                    , privdP   :: w           -- ^ d mod (p-1)
                    , privdQ   :: w           -- ^ d mod (q-1)
                    , privQInv :: w           -- ^ q^(-1) mod p
                    } deriving Show

instance Eq w => Eq (PublicKey w) where
  (==) (PublicKey n1 e1) (PublicKey n2 e2) = (n1  ==  n2) `safeAnd`
                                             (e1  ==  e2)

instance Eq w => Eq (PrivateKey w) where
  (==) (PrivateKey n1 e1 d1 p1 q1 dp1 dq1 iqp1)
       (PrivateKey n2 e2 d2 p2 q2 dp2 dq2 iqp2) = (n1    ==    n2) `safeAnd`
                                                  (e1    ==    e2) `safeAnd`
                                                  (d1    ==    d2) `safeAnd`
                                                  (p1    ==    p2) `safeAnd`
                                                  (q1    ==    q2) `safeAnd`
                                                  (dp1   ==   dp2) `safeAnd`
                                                  (dq1   ==   dq2) `safeAnd`
                                                  (iqp1  ==  iqp2)

instance Storable w => Storable (PublicKey w) where
  sizeOf _     = 2 * sizeOf (undefined :: w)
  alignment _  = alignment (undefined :: w)
  peek ptr     = runParser (castPtr ptr) $ PublicKey <$> parseStorable
                                                     <*> parseStorable
  poke ptr k   = runWrite (castPtr ptr) $  writeStorable (pubN k)
                                        <> writeStorable (pubE k)

instance Storable w => Storable (PrivateKey w) where
  sizeOf _     = 8 * sizeOf (undefined :: w)
  alignment _  = alignment (undefined :: w)
  peek ptr     = runParser (castPtr ptr) $ PrivateKey <$> parseStorable
                                                      <*> parseStorable
                                                      <*> parseStorable
                                                      <*> parseStorable
                                                      <*> parseStorable
                                                      <*> parseStorable
                                                      <*> parseStorable
                                                      <*> parseStorable
  poke ptr k   = runWrite (castPtr ptr) $  writeStorable (privN k)
                                        <> writeStorable (privE k)
                                        <> writeStorable (privD k)
                                        <> writeStorable (privP k)
                                        <> writeStorable (privQ k)
                                        <> writeStorable (privdP k)
                                        <> writeStorable (privdQ k)
                                        <> writeStorable (privQInv k)

-- | Stores individual words in Big Endian.
instance (Num w, Storable w, Integral w) => EndianStore (PublicKey w) where
  load cptr    = runParser cptr $ PublicKey <$> parseWordBE <*> parseWordBE
  store cptr k = runWrite cptr  $  writeWordBE (pubN k)
                                <> writeWordBE (pubE k)

instance (Num w, Storable w, Integral w) => CryptoSerialize (PublicKey w)

-- | Stores individual words in Big Endian.
instance (Num w, Storable w, Integral w) => EndianStore (PrivateKey w) where
  load ptr     = runParser ptr $ PrivateKey <$> parseWordBE
                                            <*> parseWordBE
                                            <*> parseWordBE
                                            <*> parseWordBE
                                            <*> parseWordBE
                                            <*> parseWordBE
                                            <*> parseWordBE
                                            <*> parseWordBE

  store ptr k   = runWrite ptr $  writeWordBE (privN k)
                               <> writeWordBE (privE k)
                               <> writeWordBE (privD k)
                               <> writeWordBE (privP k)
                               <> writeWordBE (privQ k)
                               <> writeWordBE (privdP k)
                               <> writeWordBE (privdQ k)
                               <> writeWordBE (privQInv k)

instance (Num w, Storable w, Integral w) => CryptoSerialize (PrivateKey w)

-- | RSA type. @k@ is key size (eg `Word1024`), @h@ is the underlying
-- hash used, @n@ is RSAMode (eg. `PKCS`) and @mode@ is mode of
-- operation (eg `SignMode`, `EncryptMode`)
#if UseKinds
newtype RSA k h (n :: RSAMode) (mode :: Mode) = RSA k
  deriving (Show, Eq, Num, Integral, Storable, Bits, Real, Ord, Enum)
#else
newtype RSA k h n mode = RSA k
  deriving (Show, Eq, Num, Integral, Storable, Bits, Real, Ord, Enum)
{-# DEPRECATED RSA
   "Kind restriction on n and mode will be added from GHC 7.6 onwards" #-}
#endif

#if UseKinds
-- | RSA modes
data RSAMode = OAEP
             | PKCS
             | PSS
               deriving (Show, Eq)
#else
-- | OAEP mode
data OAEP = OAEP deriving (Show, Eq)

-- | PKCS mode
data PKCS = PKCS deriving (Show, Eq)

-- | PSS mode
data PSS = PSS deriving (Show, Eq)
#endif

-- | RSA Gadget
#if UseKinds
data RSAGadget k g (n :: RSAMode) (m :: Mode) =
#else
data RSAGadget k g n m =
#endif
     RSAGadget (RSAMem k m) g


-- | This is a helper type family to unify Auth, Verify, Encrypt and
-- Decrypt Gadgets in the same RSAGadget. It changes the type of
-- Gadget's memory depending on Mode.
#if UseKinds
type family RSAMem k (m :: Mode) :: *
#else
type family RSAMem k m :: *
#endif

type instance RSAMem k SignMode = CryptoCell (PrivateKey k)
type instance RSAMem k VerifyMode = (CryptoCell (PublicKey k), CryptoCell k)

type instance RSAMem k EncryptMode = CryptoCell (PublicKey k)
type instance RSAMem k DecryptMode = CryptoCell (PrivateKey k)

keySize :: Storable w => k w -> BYTES Int
keySize = BYTES . sizeOf . getW
  where getW :: k w -> w
        getW = undefined
{-# SPECIALIZE keySize :: PublicKey Word1024 -> BYTES Int #-}
{-# SPECIALIZE keySize :: PublicKey Word2048 -> BYTES Int #-}
{-# SPECIALIZE keySize :: PublicKey Word4096 -> BYTES Int #-}
{-# SPECIALIZE keySize :: PrivateKey Word1024 -> BYTES Int #-}
{-# SPECIALIZE keySize :: PrivateKey Word2048 -> BYTES Int #-}
{-# SPECIALIZE keySize :: PrivateKey Word4096 -> BYTES Int #-}


-- | Xor two bytestring. If bytestrings are of different length then
-- the larger one is truncated to the length of shorter one.
xorByteString :: ByteString -> ByteString -> ByteString
xorByteString o1 o2 = BS.pack $ BS.zipWith xor o1 o2

-- | Mask Function
type MGF = ByteString -> BYTES Int -> ByteString
