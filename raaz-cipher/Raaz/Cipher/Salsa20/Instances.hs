{- |

This module provides required instances for Salsa20 Cipher.

-}
{-# LANGUAGE TypeFamilies                  #-}
{-# LANGUAGE FlexibleInstances             #-}
{-# LANGUAGE FlexibleContexts              #-}
{-# LANGUAGE ScopedTypeVariables           #-}
{-# LANGUAGE ForeignFunctionInterface      #-}
{-# OPTIONS_GHC -fno-warn-orphans          #-}
{-# CFILES raaz/cipher/cportable/salsa20.c #-}

module Raaz.Cipher.Salsa20.Instances () where

import Control.Applicative
import Control.Monad
import Data.Bits
import Data.ByteString                    (unpack)
import Data.Word
import Foreign.Ptr
import Foreign.Storable

import Raaz.Memory
import Raaz.Primitives
import Raaz.Primitives.Cipher
import Raaz.Types
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

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R20) KEY128 EncryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R20) KEY128 EncryptMode)) = Cipher (Salsa20 R20) KEY128 EncryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R20) KEY128 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_20Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_20Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 20)

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R20) KEY128 DecryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R20) KEY128 DecryptMode)) = Cipher (Salsa20 R20) KEY128 DecryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R20) KEY128 DecryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_20Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_20Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 20)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R20) KEY256 EncryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R20) KEY256 EncryptMode)) = Cipher (Salsa20 R20) KEY256 EncryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R20) KEY256 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_20Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_20Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 20)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R20) KEY256 DecryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R20) KEY256 DecryptMode)) = Cipher (Salsa20 R20) KEY256 DecryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R20) KEY256 DecryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_20Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_20Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 20)

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R20) KEY128 EncryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R20) KEY128 EncryptMode)) = Cipher (Salsa20 R20) KEY128 EncryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R20) KEY128 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_20Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_20Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_20

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R20) KEY128 DecryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R20) KEY128 DecryptMode)) = Cipher (Salsa20 R20) KEY128 DecryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R20) KEY128 DecryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_20Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_20Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_20

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R20) KEY256 EncryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R20) KEY256 EncryptMode)) = Cipher (Salsa20 R20) KEY256 EncryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R20) KEY256 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_20Cxt (k,n,s)) = cExpand256 mc k n s
  finalize (CGadget mc) = Salsa20_20Cxt . compress256 <$> cellLoad mc
  apply = applyCGad c_salsa20_20

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R20) KEY256 DecryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R20) KEY256 DecryptMode)) = Cipher (Salsa20 R20) KEY256 DecryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R20) KEY256 DecryptMode)) = CryptoCell Matrix
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

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R12) KEY128 EncryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R12) KEY128 EncryptMode)) = Cipher (Salsa20 R12) KEY128 EncryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R12) KEY128 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_12Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_12Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 12)

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R12) KEY128 DecryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R12) KEY128 DecryptMode)) = Cipher (Salsa20 R12) KEY128 DecryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R12) KEY128 DecryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_12Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_12Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 12)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R12) KEY256 EncryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R12) KEY256 EncryptMode)) = Cipher (Salsa20 R12) KEY256 EncryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R12) KEY256 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_12Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_12Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 12)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R12) KEY256 DecryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R12) KEY256 DecryptMode)) = Cipher (Salsa20 R12) KEY256 DecryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R12) KEY256 DecryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_12Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_12Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 12)

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R12) KEY128 EncryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R12) KEY128 EncryptMode)) = Cipher (Salsa20 R12) KEY128 EncryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R12) KEY128 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_12Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_12Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_12

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R12) KEY128 DecryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R12) KEY128 DecryptMode)) = Cipher (Salsa20 R12) KEY128 DecryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R12) KEY128 DecryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_12Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_12Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_12

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R12) KEY256 EncryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R12) KEY256 EncryptMode)) = Cipher (Salsa20 R12) KEY256 EncryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R12) KEY256 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_12Cxt (k,n,s)) = cExpand256 mc k n s
  finalize (CGadget mc) = Salsa20_12Cxt . compress256 <$> cellLoad mc
  apply = applyCGad c_salsa20_12

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R12) KEY256 DecryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R12) KEY256 DecryptMode)) = Cipher (Salsa20 R12) KEY256 DecryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R12) KEY256 DecryptMode)) = CryptoCell Matrix
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

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R8) KEY128 EncryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R8) KEY128 EncryptMode)) = Cipher (Salsa20 R8) KEY128 EncryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R8) KEY128 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_8Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_8Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 8)

-- | Reference Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R8) KEY128 DecryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R8) KEY128 DecryptMode)) = Cipher (Salsa20 R8) KEY128 DecryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R8) KEY128 DecryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_8Cxt (k,n,s)) = cellStore mc $ expand128 k n s
  finalize (HGadget mc) = Salsa20_8Cxt . compress128 <$> cellLoad mc
  apply g = applyGad g (salsa20 8)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R8) KEY256 EncryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R8) KEY256 EncryptMode)) = Cipher (Salsa20 R8) KEY256 EncryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R8) KEY256 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_8Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_8Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 8)

-- | Reference Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (HGadget (Cipher (Salsa20 R8) KEY256 DecryptMode)) where
  type PrimitiveOf (HGadget (Cipher (Salsa20 R8) KEY256 DecryptMode)) = Cipher (Salsa20 R8) KEY256 DecryptMode
  type MemoryOf (HGadget (Cipher (Salsa20 R8) KEY256 DecryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . HGadget
  initialize (HGadget mc) (Salsa20_8Cxt (k,n,s)) = cellStore mc $ expand256 k n s
  finalize (HGadget mc) = Salsa20_8Cxt . compress256 <$> cellLoad mc
  apply g = applyGad g (salsa20 8)

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R8) KEY128 EncryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R8) KEY128 EncryptMode)) = Cipher (Salsa20 R8) KEY128 EncryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R8) KEY128 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_8Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_8Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_8

-- | CPortable Gadget instance for Salsa 20 with 16 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R8) KEY128 DecryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R8) KEY128 DecryptMode)) = Cipher (Salsa20 R8) KEY128 DecryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R8) KEY128 DecryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_8Cxt (k,n,s)) = cExpand128 mc k n s
  finalize (CGadget mc) = Salsa20_8Cxt . compress128 <$> cellLoad mc
  apply = applyCGad c_salsa20_8

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R8) KEY256 EncryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R8) KEY256 EncryptMode)) = Cipher (Salsa20 R8) KEY256 EncryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R8) KEY256 EncryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_8Cxt (k,n,s)) = cExpand256 mc k n s
  finalize (CGadget mc) = Salsa20_8Cxt . compress256 <$> cellLoad mc
  apply = applyCGad c_salsa20_8

-- | CPortable Gadget instance for Salsa 20 with 32 Byte KEY
instance Gadget (CGadget (Cipher (Salsa20 R8) KEY256 DecryptMode)) where
  type PrimitiveOf (CGadget (Cipher (Salsa20 R8) KEY256 DecryptMode)) = Cipher (Salsa20 R8) KEY256 DecryptMode
  type MemoryOf (CGadget (Cipher (Salsa20 R8) KEY256 DecryptMode)) = CryptoCell Matrix
  newGadgetWithMemory = return . CGadget
  initialize (CGadget mc) (Salsa20_8Cxt (k,n,s)) = cExpand256 mc k n s
  finalize (CGadget mc) = Salsa20_8Cxt . compress256 <$> cellLoad mc
  apply = applyCGad c_salsa20_8

applyGad :: (Integral i, Gadget (HGadget t), MemoryOf (HGadget t) ~ CryptoCell Matrix)
            => HGadget t -> (Matrix -> Matrix) -> i -> CryptoPtr -> IO ()
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

applyCGad :: (CryptoCoerce s (BYTES Int),MemoryOf (CGadget t) ~ CryptoCell a)
             => (CryptoPtr -> x -> BYTES Int -> IO b) -> CGadget t -> s -> x -> IO b
applyCGad with (CGadget mc) n cptr = withCell mc go
  where
    go mptr = with mptr cptr (cryptoCoerce n :: BYTES Int)
{-# INLINE applyCGad #-}

instance CryptoPrimitive (Cipher (Salsa20 R20) KEY128 EncryptMode) where
  type Recommended (Cipher (Salsa20 R20) KEY128 EncryptMode) = CGadget (Cipher (Salsa20 R20) KEY128 EncryptMode)
  type Reference (Cipher (Salsa20 R20) KEY128 EncryptMode) = HGadget (Cipher (Salsa20 R20) KEY128 EncryptMode)

instance CryptoPrimitive (Cipher (Salsa20 R20) KEY128 DecryptMode) where
  type Recommended (Cipher (Salsa20 R20) KEY128 DecryptMode) = CGadget (Cipher (Salsa20 R20) KEY128 DecryptMode)
  type Reference (Cipher (Salsa20 R20) KEY128 DecryptMode) = HGadget (Cipher (Salsa20 R20) KEY128 DecryptMode)

instance CryptoPrimitive (Cipher (Salsa20 R20) KEY256 EncryptMode) where
  type Recommended (Cipher (Salsa20 R20) KEY256 EncryptMode) = CGadget (Cipher (Salsa20 R20) KEY256 EncryptMode)
  type Reference (Cipher (Salsa20 R20) KEY256 EncryptMode) = HGadget (Cipher (Salsa20 R20) KEY256 EncryptMode)

instance CryptoPrimitive (Cipher (Salsa20 R20) KEY256 DecryptMode) where
  type Recommended (Cipher (Salsa20 R20) KEY256 DecryptMode) = CGadget (Cipher (Salsa20 R20) KEY256 DecryptMode)
  type Reference (Cipher (Salsa20 R20) KEY256 DecryptMode) = HGadget (Cipher (Salsa20 R20) KEY256 DecryptMode)

instance StreamGadget (CGadget (Cipher (Salsa20 R20) KEY128 EncryptMode))
instance StreamGadget (CGadget (Cipher (Salsa20 R20) KEY128 DecryptMode))
instance StreamGadget (CGadget (Cipher (Salsa20 R20) KEY256 EncryptMode))
instance StreamGadget (CGadget (Cipher (Salsa20 R20) KEY256 DecryptMode))

instance StreamGadget (HGadget (Cipher (Salsa20 R20) KEY128 EncryptMode))
instance StreamGadget (HGadget (Cipher (Salsa20 R20) KEY128 DecryptMode))
instance StreamGadget (HGadget (Cipher (Salsa20 R20) KEY256 EncryptMode))
instance StreamGadget (HGadget (Cipher (Salsa20 R20) KEY256 DecryptMode))

instance CryptoPrimitive (Cipher (Salsa20 R12) KEY128 EncryptMode) where
  type Recommended (Cipher (Salsa20 R12) KEY128 EncryptMode) = CGadget (Cipher (Salsa20 R12) KEY128 EncryptMode)
  type Reference (Cipher (Salsa20 R12) KEY128 EncryptMode) = HGadget (Cipher (Salsa20 R12) KEY128 EncryptMode)

instance CryptoPrimitive (Cipher (Salsa20 R12) KEY128 DecryptMode) where
  type Recommended (Cipher (Salsa20 R12) KEY128 DecryptMode) = CGadget (Cipher (Salsa20 R12) KEY128 DecryptMode)
  type Reference (Cipher (Salsa20 R12) KEY128 DecryptMode) = HGadget (Cipher (Salsa20 R12) KEY128 DecryptMode)

instance CryptoPrimitive (Cipher (Salsa20 R12) KEY256 EncryptMode) where
  type Recommended (Cipher (Salsa20 R12) KEY256 EncryptMode) = CGadget (Cipher (Salsa20 R12) KEY256 EncryptMode)
  type Reference (Cipher (Salsa20 R12) KEY256 EncryptMode) = HGadget (Cipher (Salsa20 R12) KEY256 EncryptMode)

instance CryptoPrimitive (Cipher (Salsa20 R12) KEY256 DecryptMode) where
  type Recommended (Cipher (Salsa20 R12) KEY256 DecryptMode) = CGadget (Cipher (Salsa20 R12) KEY256 DecryptMode)
  type Reference (Cipher (Salsa20 R12) KEY256 DecryptMode) = HGadget (Cipher (Salsa20 R12) KEY256 DecryptMode)

instance StreamGadget (CGadget (Cipher (Salsa20 R12) KEY128 EncryptMode))
instance StreamGadget (CGadget (Cipher (Salsa20 R12) KEY128 DecryptMode))
instance StreamGadget (CGadget (Cipher (Salsa20 R12) KEY256 EncryptMode))
instance StreamGadget (CGadget (Cipher (Salsa20 R12) KEY256 DecryptMode))

instance StreamGadget (HGadget (Cipher (Salsa20 R12) KEY128 EncryptMode))
instance StreamGadget (HGadget (Cipher (Salsa20 R12) KEY128 DecryptMode))
instance StreamGadget (HGadget (Cipher (Salsa20 R12) KEY256 EncryptMode))
instance StreamGadget (HGadget (Cipher (Salsa20 R12) KEY256 DecryptMode))

instance CryptoPrimitive (Cipher (Salsa20 R8) KEY128 EncryptMode) where
  type Recommended (Cipher (Salsa20 R8) KEY128 EncryptMode) = CGadget (Cipher (Salsa20 R8) KEY128 EncryptMode)
  type Reference (Cipher (Salsa20 R8) KEY128 EncryptMode) = HGadget (Cipher (Salsa20 R8) KEY128 EncryptMode)

instance CryptoPrimitive (Cipher (Salsa20 R8) KEY128 DecryptMode) where
  type Recommended (Cipher (Salsa20 R8) KEY128 DecryptMode) = CGadget (Cipher (Salsa20 R8) KEY128 DecryptMode)
  type Reference (Cipher (Salsa20 R8) KEY128 DecryptMode) = HGadget (Cipher (Salsa20 R8) KEY128 DecryptMode)

instance CryptoPrimitive (Cipher (Salsa20 R8) KEY256 EncryptMode) where
  type Recommended (Cipher (Salsa20 R8) KEY256 EncryptMode) = CGadget (Cipher (Salsa20 R8) KEY256 EncryptMode)
  type Reference (Cipher (Salsa20 R8) KEY256 EncryptMode) = HGadget (Cipher (Salsa20 R8) KEY256 EncryptMode)

instance CryptoPrimitive (Cipher (Salsa20 R8) KEY256 DecryptMode) where
  type Recommended (Cipher (Salsa20 R8) KEY256 DecryptMode) = CGadget (Cipher (Salsa20 R8) KEY256 DecryptMode)
  type Reference (Cipher (Salsa20 R8) KEY256 DecryptMode) = HGadget (Cipher (Salsa20 R8) KEY256 DecryptMode)

instance StreamGadget (CGadget (Cipher (Salsa20 R8) KEY128 EncryptMode))
instance StreamGadget (CGadget (Cipher (Salsa20 R8) KEY128 DecryptMode))
instance StreamGadget (CGadget (Cipher (Salsa20 R8) KEY256 EncryptMode))
instance StreamGadget (CGadget (Cipher (Salsa20 R8) KEY256 DecryptMode))

instance StreamGadget (HGadget (Cipher (Salsa20 R8) KEY128 EncryptMode))
instance StreamGadget (HGadget (Cipher (Salsa20 R8) KEY128 DecryptMode))
instance StreamGadget (HGadget (Cipher (Salsa20 R8) KEY256 EncryptMode))
instance StreamGadget (HGadget (Cipher (Salsa20 R8) KEY256 DecryptMode))

counter0 :: Counter
counter0 = Counter (SplitWord64 0 0)

instance Encrypt (Cipher (Salsa20 R20) KEY128) where
  encryptCxt (k,n) = Salsa20_20Cxt (k,n,counter0)
  decryptCxt (k,n) = Salsa20_20Cxt (k,n,counter0)

instance Encrypt (Cipher (Salsa20 R20) KEY256) where
  encryptCxt (k,n) = Salsa20_20Cxt (k,n,counter0)
  decryptCxt (k,n) = Salsa20_20Cxt (k,n,counter0)

instance Encrypt (Cipher (Salsa20 R12) KEY128) where
  encryptCxt (k,n) = Salsa20_12Cxt (k,n,counter0)
  decryptCxt (k,n) = Salsa20_12Cxt (k,n,counter0)

instance Encrypt (Cipher (Salsa20 R12) KEY256) where
  encryptCxt (k,n) = Salsa20_12Cxt (k,n,counter0)
  decryptCxt (k,n) = Salsa20_12Cxt (k,n,counter0)

instance Encrypt (Cipher (Salsa20 R8) KEY128) where
  encryptCxt (k,n) = Salsa20_8Cxt (k,n,counter0)
  decryptCxt (k,n) = Salsa20_8Cxt (k,n,counter0)

instance Encrypt (Cipher (Salsa20 R8) KEY256) where
  encryptCxt (k,n) = Salsa20_8Cxt (k,n,counter0)
  decryptCxt (k,n) = Salsa20_8Cxt (k,n,counter0)

type instance Key (Cipher (Salsa20 R20) KEY128 EncryptMode) = (KEY128,Nonce)
type instance Key (Cipher (Salsa20 R20) KEY128 DecryptMode) = (KEY128,Nonce)

type instance Key (Cipher (Salsa20 R20) KEY256 EncryptMode) = (KEY256,Nonce)
type instance Key (Cipher (Salsa20 R20) KEY256 DecryptMode) = (KEY256,Nonce)

type instance Key (Cipher (Salsa20 R12) KEY128 EncryptMode) = (KEY128,Nonce)
type instance Key (Cipher (Salsa20 R12) KEY128 DecryptMode) = (KEY128,Nonce)

type instance Key (Cipher (Salsa20 R12) KEY256 EncryptMode) = (KEY256,Nonce)
type instance Key (Cipher (Salsa20 R12) KEY256 DecryptMode) = (KEY256,Nonce)

type instance Key (Cipher (Salsa20 R8) KEY128 EncryptMode) = (KEY128,Nonce)
type instance Key (Cipher (Salsa20 R8) KEY128 DecryptMode) = (KEY128,Nonce)

type instance Key (Cipher (Salsa20 R8) KEY256 EncryptMode) = (KEY256,Nonce)
type instance Key (Cipher (Salsa20 R8) KEY256 DecryptMode) = (KEY256,Nonce)
