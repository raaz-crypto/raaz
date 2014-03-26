{- |

This module provides required instances for Salsa20 Cipher.

-}
{-# LANGUAGE TypeFamilies                  #-}
{-# LANGUAGE FlexibleInstances             #-}
{-# LANGUAGE ScopedTypeVariables           #-}
{-# LANGUAGE ForeignFunctionInterface      #-}
{-# OPTIONS_GHC -fno-warn-orphans          #-}
{-# CFILES raaz/cipher/cportable/salsa20.c #-}

module Raaz.Cipher.Salsa20.Instances () where

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.ByteString                    (unpack)
import qualified Data.ByteString as BS
import Data.Word
import Foreign.Ptr
import Foreign.Storable

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
import Raaz.Util.ByteString
import Raaz.Util.Ptr

import Raaz.Cipher.Salsa20.Block.Internal
import Raaz.Cipher.Salsa20.Block.Type
import Raaz.Cipher.Salsa20.Internal

foreign import ccall unsafe
  "raaz/cipher/cportable/salsa20.c expand128"
  c_expand128  :: CryptoPtr -- ^ IV = (Key || Nonce || Counter)
               -> CryptoPtr -- ^ expanded key
               -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/salsa20.c expand256"
  c_expand256  :: CryptoPtr  -- ^ IV = (Key || Nonce || Counter)
               -> CryptoPtr  -- ^ expanded key
               -> IO ()

cExpansionWith :: EndianStore k
                => (CryptoPtr -> CryptoPtr -> IO ())
                -> CryptoCell Matrix
                -> k
                -> Nonce
                -> Counter
                -> IO ()
cExpansionWith with mc key nonce cntr = withCell mc (expand key nonce  cntr)
  where
    szk = BYTES $ sizeOf key + sizeOf nonce + sizeOf cntr
    expand k n c mptr = allocaBuffer szk $ \tempptr -> do
      store tempptr k
      let tempptrn = tempptr `plusPtr` sizeOf k
      store tempptrn n
      let tempptrc = tempptrn `plusPtr` sizeOf n
      store tempptrc c
      with tempptr mptr
{-# INLINE cExpansionWith #-}

cExpand128 :: CryptoCell Matrix -> KEY128 -> Nonce -> Counter -> IO ()
cExpand128 = cExpansionWith c_expand128
{-# INLINE cExpand128 #-}

cExpand256 :: CryptoCell Matrix -> KEY256 -> Nonce -> Counter -> IO ()
cExpand256 = cExpansionWith c_expand256
{-# INLINE cExpand256 #-}

foreign import ccall unsafe
  "raaz/cipher/cportable/salsa20.c salsa20_20"
  c_salsa20_20  :: CryptoPtr  -- ^ Expanded Key
                -> CryptoPtr  -- ^ Input
                -> BYTES Int  -- ^ Number of Bytes
                -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/salsa20.c salsa20_12"
  c_salsa20_12  :: CryptoPtr  -- ^ Expanded Key
                -> CryptoPtr  -- ^ Input
                -> BYTES Int  -- ^ Number of Bytes
                -> IO ()

foreign import ccall unsafe
  "raaz/cipher/cportable/salsa20.c salsa20_8"
  c_salsa20_8  :: CryptoPtr  -- ^ Expanded Key
               -> CryptoPtr  -- ^ Input
               -> BYTES Int  -- ^ Number of Bytes
               -> IO ()


-------------------------------- Salsa20 Group 20 -------------------------
-- | Primitive instance for Salsa20 where Context includes the Key,
-- Nonce (8 Byte) and Counter (8 Byte).
instance Primitive (Cipher (Salsa20 R20) k e) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (Cipher (Salsa20 R20) k e) = Salsa20_20Cxt (k, Nonce, Counter)
                                         deriving (Eq,Show)

-- | Initializable instance where the given bytestring is as (key ||
-- nonce || counter)
instance EndianStore k => Initializable (Cipher (Salsa20 R20) k e) where
  cxtSize _ = BYTES (ksz + nsz + csz)
    where
      ksz = sizeOf (undefined :: k)
      nsz = sizeOf (undefined :: Nonce)
      csz = sizeOf (undefined :: Counter)
  {-# INLINE cxtSize #-}
  getCxt = Salsa20_20Cxt . get
    where
      get bs = (k,n,c)
        where
          k = fromByteString kbs
          n = fromByteString nbs
          c = fromByteString cbs
          (kbs,rest) = BS.splitAt (sizeOf k) bs
          (nbs,cbs) = BS.splitAt (sizeOf n) rest

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R20) KEY128 Encryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R20) KEY128 Encryption)) = Cipher (Salsa20 R20) KEY128 Encryption
  type MemoryOf (HGadget (Cipher (Salsa20 R20) KEY128 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_20Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_20Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 20)

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R20) KEY128 Decryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R20) KEY128 Decryption)) = Cipher (Salsa20 R20) KEY128 Decryption
  type MemoryOf (HGadget (Cipher (Salsa20 R20) KEY128 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_20Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_20Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 20)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R20) KEY256 Encryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R20) KEY256 Encryption)) = Cipher (Salsa20 R20) KEY256 Encryption
  type MemoryOf (HGadget (Cipher (Salsa20 R20) KEY256 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_20Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_20Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 20)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R20) KEY256 Decryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R20) KEY256 Decryption)) = Cipher (Salsa20 R20) KEY256 Decryption
  type MemoryOf (HGadget (Cipher (Salsa20 R20) KEY256 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_20Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_20Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 20)

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R20) KEY128 Encryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R20) KEY128 Encryption)) = Cipher (Salsa20 R20) KEY128 Encryption
  type MemoryOf (CGadget (Cipher (Salsa20 R20) KEY128 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_20Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_20Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_20

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R20) KEY128 Decryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R20) KEY128 Decryption)) = Cipher (Salsa20 R20) KEY128 Decryption
  type MemoryOf (CGadget (Cipher (Salsa20 R20) KEY128 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_20Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_20Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_20

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R20) KEY256 Encryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R20) KEY256 Encryption)) = Cipher (Salsa20 R20) KEY256 Encryption
  type MemoryOf (CGadget (Cipher (Salsa20 R20) KEY256 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_20Cxt (k,n,s)) = cExpand256 mc k n s
  finalize (CGadget mc) = Salsa20_20Cxt . compress256 <$> cellLoad mc
  apply = applyCGad c_salsa20_20

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R20) KEY256 Decryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R20) KEY256 Decryption)) = Cipher (Salsa20 R20) KEY256 Decryption
  type MemoryOf (CGadget (Cipher (Salsa20 R20) KEY256 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_20Cxt (k,n,s)) = cExpand256 mc k n s
  finalize (CGadget mc) = Salsa20_20Cxt . compress256 <$> cellLoad mc
  apply = applyCGad c_salsa20_20

------------------------------------------ Salsa20 Round 12 --------------------

-- | Primitive instance for Salsa20 where Context includes the Key,
-- Nonce (8 Byte) and Counter (8 Byte).
instance Primitive (Cipher (Salsa20 R12) k e) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (Cipher (Salsa20 R12) k e) = Salsa20_12Cxt (k, Nonce, Counter)
                                         deriving (Eq,Show)

-- | Initializable instance where the given bytestring is as (key ||
-- nonce || counter)
instance EndianStore k => Initializable (Cipher (Salsa20 R12) k e) where
  cxtSize _ = BYTES (ksz + nsz + csz)
    where
      ksz = sizeOf (undefined :: k)
      nsz = sizeOf (undefined :: Nonce)
      csz = sizeOf (undefined :: Counter)
  {-# INLINE cxtSize #-}
  getCxt = Salsa20_12Cxt . get
    where
      get bs = (k,n,c)
        where
          k = fromByteString kbs
          n = fromByteString nbs
          c = fromByteString cbs
          (kbs,rest) = BS.splitAt (sizeOf k) bs
          (nbs,cbs) = BS.splitAt (sizeOf n) rest

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R12) KEY128 Encryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R12) KEY128 Encryption)) = Cipher (Salsa20 R12) KEY128 Encryption
  type MemoryOf (HGadget (Cipher (Salsa20 R12) KEY128 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_12Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_12Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 12)

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R12) KEY128 Decryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R12) KEY128 Decryption)) = Cipher (Salsa20 R12) KEY128 Decryption
  type MemoryOf (HGadget (Cipher (Salsa20 R12) KEY128 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_12Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_12Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 12)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R12) KEY256 Encryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R12) KEY256 Encryption)) = Cipher (Salsa20 R12) KEY256 Encryption
  type MemoryOf (HGadget (Cipher (Salsa20 R12) KEY256 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_12Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_12Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 12)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R12) KEY256 Decryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R12) KEY256 Decryption)) = Cipher (Salsa20 R12) KEY256 Decryption
  type MemoryOf (HGadget (Cipher (Salsa20 R12) KEY256 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_12Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_12Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 12)

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R12) KEY128 Encryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R12) KEY128 Encryption)) = Cipher (Salsa20 R12) KEY128 Encryption
  type MemoryOf (CGadget (Cipher (Salsa20 R12) KEY128 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_12Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_12Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_12

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R12) KEY128 Decryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R12) KEY128 Decryption)) = Cipher (Salsa20 R12) KEY128 Decryption
  type MemoryOf (CGadget (Cipher (Salsa20 R12) KEY128 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_12Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_12Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_12

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R12) KEY256 Encryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R12) KEY256 Encryption)) = Cipher (Salsa20 R12) KEY256 Encryption
  type MemoryOf (CGadget (Cipher (Salsa20 R12) KEY256 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_12Cxt (k,n,s)) = cExpand256 mc k n s
  finalize (CGadget mc) = Salsa20_12Cxt . compress256 <$> cellLoad mc
  apply = applyCGad c_salsa20_12

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R12) KEY256 Decryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R12) KEY256 Decryption)) = Cipher (Salsa20 R12) KEY256 Decryption
  type MemoryOf (CGadget (Cipher (Salsa20 R12) KEY256 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_12Cxt (k,n,s)) = cExpand256 mc k n s
  finalize (CGadget mc) = Salsa20_12Cxt . compress256 <$> cellLoad mc
  apply = applyCGad c_salsa20_12

------------------------------------------------ Salsa20 Round 8 ---------------

  -- | Primitive instance for Salsa20 where Context includes the Key,
-- Nonce (8 Byte) and Counter (8 Byte).
instance Primitive (Cipher (Salsa20 R8) k e) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (Cipher (Salsa20 R8) k e) = Salsa20_8Cxt (k, Nonce, Counter)
                                         deriving (Eq,Show)

-- | Initializable instance where the given bytestring is as (key ||
-- nonce || counter)
instance EndianStore k => Initializable (Cipher (Salsa20 R8) k e) where
  cxtSize _ = BYTES (ksz + nsz + csz)
    where
      ksz = sizeOf (undefined :: k)
      nsz = sizeOf (undefined :: Nonce)
      csz = sizeOf (undefined :: Counter)
  {-# INLINE cxtSize #-}
  getCxt = Salsa20_8Cxt . get
    where
      get bs = (k,n,c)
        where
          k = fromByteString kbs
          n = fromByteString nbs
          c = fromByteString cbs
          (kbs,rest) = BS.splitAt (sizeOf k) bs
          (nbs,cbs) = BS.splitAt (sizeOf n) rest

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R8) KEY128 Encryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R8) KEY128 Encryption)) = Cipher (Salsa20 R8) KEY128 Encryption
  type MemoryOf (HGadget (Cipher (Salsa20 R8) KEY128 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_8Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_8Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 8)

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R8) KEY128 Decryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R8) KEY128 Decryption)) = Cipher (Salsa20 R8) KEY128 Decryption
  type MemoryOf (HGadget (Cipher (Salsa20 R8) KEY128 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_8Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_8Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 8)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R8) KEY256 Encryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R8) KEY256 Encryption)) = Cipher (Salsa20 R8) KEY256 Encryption
  type MemoryOf (HGadget (Cipher (Salsa20 R8) KEY256 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_8Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_8Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 8)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R8) KEY256 Decryption)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R8) KEY256 Decryption)) = Cipher (Salsa20 R8) KEY256 Decryption
  type MemoryOf (HGadget (Cipher (Salsa20 R8) KEY256 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_8Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_8Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 8)

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R8) KEY128 Encryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R8) KEY128 Encryption)) = Cipher (Salsa20 R8) KEY128 Encryption
  type MemoryOf (CGadget (Cipher (Salsa20 R8) KEY128 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_8Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_8Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_8

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R8) KEY128 Decryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R8) KEY128 Decryption)) = Cipher (Salsa20 R8) KEY128 Decryption
  type MemoryOf (CGadget (Cipher (Salsa20 R8) KEY128 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_8Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_8Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_8

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R8) KEY256 Encryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R8) KEY256 Encryption)) = Cipher (Salsa20 R8) KEY256 Encryption
  type MemoryOf (CGadget (Cipher (Salsa20 R8) KEY256 Encryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_8Cxt (k,n,s)) = cExpand256 mc k n s
  finalize (CGadget mc) = Salsa20_8Cxt . compress256 <$> cellLoad mc
  apply = applyCGad c_salsa20_8

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R8) KEY256 Decryption)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R8) KEY256 Decryption)) = Cipher (Salsa20 R8) KEY256 Decryption
  type MemoryOf (CGadget (Cipher (Salsa20 R8) KEY256 Decryption)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_8Cxt (k,n,s)) = cExpand256 mc k n s
  finalize (CGadget mc) = Salsa20_8Cxt . compress256 <$> cellLoad mc
  apply = applyCGad c_salsa20_8


applyGad g@(HGadget mc) with n cptr = do
    state <- cellLoad mc
    (newstate,restptr) <- foldM moveAndHash (state,cptr) [1..nblks]
    cellStore mc =<< restOfblock newstate restptr
    where
      nblks = fromIntegral n `div` fromIntegral realsz :: Int
      nextra = fromIntegral n `rem` fromIntegral realsz :: Int
      moveAndHash (cxt,ptr) _ = do
        blk <- load ptr
        let newCxt = with cxt
        store ptr $ newCxt `xorMatrix` blk
        return (incrCounter cxt, ptr `movePtr` blocksz)

      restOfblock cxt cptr' | nextra <= 0 = return cxt
                            | otherwise = do
        let newCxt = with cxt
        xorWords cptr' nextra (unpack $ toByteString newCxt)
        return $ incrCounter cxt
      xorWords :: CryptoPtr -> Int -> [Word8] -> IO ()
      xorWords _ 0 _  = return ()
      xorWords _ _ [] = return ()
      xorWords ptr left (w:ws) = do
        x <- peek (castPtr ptr)
        poke (castPtr ptr) (x `xor` w)
        xorWords (ptr `movePtr` wsize) (left-1) ws
      wsize = BYTES $ sizeOf (undefined :: Word8)
      sz = blockSize (primitiveOf g)
      blocksz = BYTES 64
      realsz = blocksz `div` sz
{-# INLINE applyGad #-}

applyCGad with (CGadget mc) n cptr = withCell mc go
  where
    go mptr = with mptr cptr (cryptoCoerce n :: BYTES Int)
{-# INLINE applyCGad #-}

instance CryptoPrimitive (Cipher (Salsa20 R20) KEY128 Encryption) where
  type Recommended (Cipher (Salsa20 R20) KEY128 Encryption) = CGadget (Cipher (Salsa20 R20) KEY128 Encryption)
  type Reference (Cipher (Salsa20 R20) KEY128 Encryption) = HGadget (Cipher (Salsa20 R20) KEY128 Encryption)

instance CryptoPrimitive (Cipher (Salsa20 R20) KEY128 Decryption) where
  type Recommended (Cipher (Salsa20 R20) KEY128 Decryption) = CGadget (Cipher (Salsa20 R20) KEY128 Decryption)
  type Reference (Cipher (Salsa20 R20) KEY128 Decryption) = HGadget (Cipher (Salsa20 R20) KEY128 Decryption)

instance CryptoPrimitive (Cipher (Salsa20 R20) KEY256 Encryption) where
  type Recommended (Cipher (Salsa20 R20) KEY256 Encryption) = CGadget (Cipher (Salsa20 R20) KEY256 Encryption)
  type Reference (Cipher (Salsa20 R20) KEY256 Encryption) = HGadget (Cipher (Salsa20 R20) KEY256 Encryption)

instance CryptoPrimitive (Cipher (Salsa20 R20) KEY256 Decryption) where
  type Recommended (Cipher (Salsa20 R20) KEY256 Decryption) = CGadget (Cipher (Salsa20 R20) KEY256 Decryption)
  type Reference (Cipher (Salsa20 R20) KEY256 Decryption) = HGadget (Cipher (Salsa20 R20) KEY256 Decryption)

instance StreamGadget (CGadget (Cipher (Salsa20 R20) KEY128 Encryption))
instance StreamGadget (CGadget (Cipher (Salsa20 R20) KEY128 Decryption))
instance StreamGadget (CGadget (Cipher (Salsa20 R20) KEY256 Encryption))
instance StreamGadget (CGadget (Cipher (Salsa20 R20) KEY256 Decryption))

instance StreamGadget (HGadget (Cipher (Salsa20 R20) KEY128 Encryption))
instance StreamGadget (HGadget (Cipher (Salsa20 R20) KEY128 Decryption))
instance StreamGadget (HGadget (Cipher (Salsa20 R20) KEY256 Encryption))
instance StreamGadget (HGadget (Cipher (Salsa20 R20) KEY256 Decryption))

instance HasInverse (HGadget (Cipher (Salsa20 R20) KEY128 Encryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R20) KEY128 Encryption)) = HGadget (Cipher (Salsa20 R20) KEY128 Decryption)

instance HasInverse (HGadget (Cipher (Salsa20 R20) KEY128 Decryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R20) KEY128 Decryption)) = HGadget (Cipher (Salsa20 R20) KEY128 Encryption)

instance HasInverse (HGadget (Cipher (Salsa20 R20) KEY256 Encryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R20) KEY256 Encryption)) = HGadget (Cipher (Salsa20 R20) KEY256 Decryption)

instance HasInverse (HGadget (Cipher (Salsa20 R20) KEY256 Decryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R20) KEY256 Decryption)) = HGadget (Cipher (Salsa20 R20) KEY256 Encryption)

instance HasInverse (CGadget (Cipher (Salsa20 R20) KEY128 Encryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R20) KEY128 Encryption)) = CGadget (Cipher (Salsa20 R20) KEY128 Decryption)

instance HasInverse (CGadget (Cipher (Salsa20 R20) KEY128 Decryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R20) KEY128 Decryption)) = CGadget (Cipher (Salsa20 R20) KEY128 Encryption)

instance HasInverse (CGadget (Cipher (Salsa20 R20) KEY256 Encryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R20) KEY256 Encryption)) = CGadget (Cipher (Salsa20 R20) KEY256 Decryption)

instance HasInverse (CGadget (Cipher (Salsa20 R20) KEY256 Decryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R20) KEY256 Decryption)) = CGadget (Cipher (Salsa20 R20) KEY256 Encryption)


instance CryptoPrimitive (Cipher (Salsa20 R12) KEY128 Encryption) where
  type Recommended (Cipher (Salsa20 R12) KEY128 Encryption) = CGadget (Cipher (Salsa20 R12) KEY128 Encryption)
  type Reference (Cipher (Salsa20 R12) KEY128 Encryption) = HGadget (Cipher (Salsa20 R12) KEY128 Encryption)

instance CryptoPrimitive (Cipher (Salsa20 R12) KEY128 Decryption) where
  type Recommended (Cipher (Salsa20 R12) KEY128 Decryption) = CGadget (Cipher (Salsa20 R12) KEY128 Decryption)
  type Reference (Cipher (Salsa20 R12) KEY128 Decryption) = HGadget (Cipher (Salsa20 R12) KEY128 Decryption)

instance CryptoPrimitive (Cipher (Salsa20 R12) KEY256 Encryption) where
  type Recommended (Cipher (Salsa20 R12) KEY256 Encryption) = CGadget (Cipher (Salsa20 R12) KEY256 Encryption)
  type Reference (Cipher (Salsa20 R12) KEY256 Encryption) = HGadget (Cipher (Salsa20 R12) KEY256 Encryption)

instance CryptoPrimitive (Cipher (Salsa20 R12) KEY256 Decryption) where
  type Recommended (Cipher (Salsa20 R12) KEY256 Decryption) = CGadget (Cipher (Salsa20 R12) KEY256 Decryption)
  type Reference (Cipher (Salsa20 R12) KEY256 Decryption) = HGadget (Cipher (Salsa20 R12) KEY256 Decryption)

instance StreamGadget (CGadget (Cipher (Salsa20 R12) KEY128 Encryption))
instance StreamGadget (CGadget (Cipher (Salsa20 R12) KEY128 Decryption))
instance StreamGadget (CGadget (Cipher (Salsa20 R12) KEY256 Encryption))
instance StreamGadget (CGadget (Cipher (Salsa20 R12) KEY256 Decryption))

instance StreamGadget (HGadget (Cipher (Salsa20 R12) KEY128 Encryption))
instance StreamGadget (HGadget (Cipher (Salsa20 R12) KEY128 Decryption))
instance StreamGadget (HGadget (Cipher (Salsa20 R12) KEY256 Encryption))
instance StreamGadget (HGadget (Cipher (Salsa20 R12) KEY256 Decryption))

instance HasInverse (HGadget (Cipher (Salsa20 R12) KEY128 Encryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R12) KEY128 Encryption)) = HGadget (Cipher (Salsa20 R12) KEY128 Decryption)

instance HasInverse (HGadget (Cipher (Salsa20 R12) KEY128 Decryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R12) KEY128 Decryption)) = HGadget (Cipher (Salsa20 R12) KEY128 Encryption)

instance HasInverse (HGadget (Cipher (Salsa20 R12) KEY256 Encryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R12) KEY256 Encryption)) = HGadget (Cipher (Salsa20 R12) KEY256 Decryption)

instance HasInverse (HGadget (Cipher (Salsa20 R12) KEY256 Decryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R12) KEY256 Decryption)) = HGadget (Cipher (Salsa20 R12) KEY256 Encryption)

instance HasInverse (CGadget (Cipher (Salsa20 R12) KEY128 Encryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R12) KEY128 Encryption)) = CGadget (Cipher (Salsa20 R12) KEY128 Decryption)

instance HasInverse (CGadget (Cipher (Salsa20 R12) KEY128 Decryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R12) KEY128 Decryption)) = CGadget (Cipher (Salsa20 R12) KEY128 Encryption)

instance HasInverse (CGadget (Cipher (Salsa20 R12) KEY256 Encryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R12) KEY256 Encryption)) = CGadget (Cipher (Salsa20 R12) KEY256 Decryption)

instance HasInverse (CGadget (Cipher (Salsa20 R12) KEY256 Decryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R12) KEY256 Decryption)) = CGadget (Cipher (Salsa20 R12) KEY256 Encryption)


instance CryptoPrimitive (Cipher (Salsa20 R8) KEY128 Encryption) where
  type Recommended (Cipher (Salsa20 R8) KEY128 Encryption) = CGadget (Cipher (Salsa20 R8) KEY128 Encryption)
  type Reference (Cipher (Salsa20 R8) KEY128 Encryption) = HGadget (Cipher (Salsa20 R8) KEY128 Encryption)

instance CryptoPrimitive (Cipher (Salsa20 R8) KEY128 Decryption) where
  type Recommended (Cipher (Salsa20 R8) KEY128 Decryption) = CGadget (Cipher (Salsa20 R8) KEY128 Decryption)
  type Reference (Cipher (Salsa20 R8) KEY128 Decryption) = HGadget (Cipher (Salsa20 R8) KEY128 Decryption)

instance CryptoPrimitive (Cipher (Salsa20 R8) KEY256 Encryption) where
  type Recommended (Cipher (Salsa20 R8) KEY256 Encryption) = CGadget (Cipher (Salsa20 R8) KEY256 Encryption)
  type Reference (Cipher (Salsa20 R8) KEY256 Encryption) = HGadget (Cipher (Salsa20 R8) KEY256 Encryption)

instance CryptoPrimitive (Cipher (Salsa20 R8) KEY256 Decryption) where
  type Recommended (Cipher (Salsa20 R8) KEY256 Decryption) = CGadget (Cipher (Salsa20 R8) KEY256 Decryption)
  type Reference (Cipher (Salsa20 R8) KEY256 Decryption) = HGadget (Cipher (Salsa20 R8) KEY256 Decryption)

instance StreamGadget (CGadget (Cipher (Salsa20 R8) KEY128 Encryption))
instance StreamGadget (CGadget (Cipher (Salsa20 R8) KEY128 Decryption))
instance StreamGadget (CGadget (Cipher (Salsa20 R8) KEY256 Encryption))
instance StreamGadget (CGadget (Cipher (Salsa20 R8) KEY256 Decryption))

instance StreamGadget (HGadget (Cipher (Salsa20 R8) KEY128 Encryption))
instance StreamGadget (HGadget (Cipher (Salsa20 R8) KEY128 Decryption))
instance StreamGadget (HGadget (Cipher (Salsa20 R8) KEY256 Encryption))
instance StreamGadget (HGadget (Cipher (Salsa20 R8) KEY256 Decryption))

instance HasInverse (HGadget (Cipher (Salsa20 R8) KEY128 Encryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R8) KEY128 Encryption)) = HGadget (Cipher (Salsa20 R8) KEY128 Decryption)

instance HasInverse (HGadget (Cipher (Salsa20 R8) KEY128 Decryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R8) KEY128 Decryption)) = HGadget (Cipher (Salsa20 R8) KEY128 Encryption)

instance HasInverse (HGadget (Cipher (Salsa20 R8) KEY256 Encryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R8) KEY256 Encryption)) = HGadget (Cipher (Salsa20 R8) KEY256 Decryption)

instance HasInverse (HGadget (Cipher (Salsa20 R8) KEY256 Decryption)) where
  type Inverse (HGadget (Cipher (Salsa20 R8) KEY256 Decryption)) = HGadget (Cipher (Salsa20 R8) KEY256 Encryption)

instance HasInverse (CGadget (Cipher (Salsa20 R8) KEY128 Encryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R8) KEY128 Encryption)) = CGadget (Cipher (Salsa20 R8) KEY128 Decryption)

instance HasInverse (CGadget (Cipher (Salsa20 R8) KEY128 Decryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R8) KEY128 Decryption)) = CGadget (Cipher (Salsa20 R8) KEY128 Encryption)

instance HasInverse (CGadget (Cipher (Salsa20 R8) KEY256 Encryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R8) KEY256 Encryption)) = CGadget (Cipher (Salsa20 R8) KEY256 Decryption)

instance HasInverse (CGadget (Cipher (Salsa20 R8) KEY256 Decryption)) where
  type Inverse (CGadget (Cipher (Salsa20 R8) KEY256 Decryption)) = CGadget (Cipher (Salsa20 R8) KEY256 Encryption)
