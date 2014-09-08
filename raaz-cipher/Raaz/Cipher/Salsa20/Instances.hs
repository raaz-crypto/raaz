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

import Control.Monad
import Data.Bits
import Data.ByteString                    (unpack)
import Data.Word
import Foreign.Ptr
import Foreign.Storable

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Cipher.Salsa20.Block.Internal
import Raaz.Cipher.Salsa20.Block.Type
import Raaz.Cipher.Salsa20.Internal

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


-- | Primitive instance for Salsa20 where Context includes the Key,
-- Nonce (8 Byte) and Counter (8 Byte).
instance Primitive (Salsa20 r k) where
  blockSize _            = BYTES 1
  {-# INLINE blockSize #-}
  type Key (Salsa20 r k) = (k, Nonce)

----------------------------- Salsa 20/8------------ ---------------------------

-- | Reference Gadget instance for Salsa20/20 with 16 Byte KEY
instance Gadget (HGadget (Salsa20 R20 KEY128)) where
  type PrimitiveOf (HGadget (Salsa20 R20 KEY128)) = Salsa20 R20 KEY128
  type MemoryOf (HGadget (Salsa20 R20 KEY128))    = SalsaMem KEY128
  newGadgetWithMemory                             = return . HGadget
  getMemory (HGadget m)                           = m
  apply g                                         = applyGad g (salsa20 20)

-- | Reference Gadget instance for Salsa20/20 with 32 Byte KEY
instance Gadget (HGadget (Salsa20 R20 KEY256)) where
  type PrimitiveOf (HGadget (Salsa20 R20 KEY256)) = Salsa20 R20 KEY256
  type MemoryOf (HGadget (Salsa20 R20 KEY256))    = SalsaMem KEY256
  newGadgetWithMemory                             = return . HGadget
  getMemory (HGadget m)                           = m
  apply g                                         = applyGad g (salsa20 20)

-- | CPortable Gadget instance for Salsa20/20 with 16 Byte KEY
instance Gadget (CGadget (Salsa20 R20 KEY128)) where
  type PrimitiveOf (CGadget (Salsa20 R20 KEY128)) = Salsa20 R20 KEY128
  type MemoryOf (CGadget (Salsa20 R20 KEY128))    = SalsaMem KEY128
  newGadgetWithMemory                             = return . CGadget
  getMemory (CGadget m)                           = m
  apply                                           = applyCGad c_salsa20_20

-- | CPortable Gadget instance for Salsa20/20 with 32 Byte KEY
instance Gadget (CGadget (Salsa20 R20 KEY256)) where
  type PrimitiveOf (CGadget (Salsa20 R20 KEY256)) = Salsa20 R20 KEY256
  type MemoryOf (CGadget (Salsa20 R20 KEY256))    = SalsaMem KEY256
  newGadgetWithMemory                             = return . CGadget
  getMemory (CGadget m)                           = m
  apply                                           = applyCGad c_salsa20_20


----------------------------- Salsa 20/12------------ ---------------------------

-- | Reference Gadget instance for Salsa20/12 with 16 Byte KEY
instance Gadget (HGadget (Salsa20 R12 KEY128)) where
  type PrimitiveOf (HGadget (Salsa20 R12 KEY128)) = Salsa20 R12 KEY128
  type MemoryOf (HGadget (Salsa20 R12 KEY128))    = SalsaMem KEY128
  newGadgetWithMemory                             = return . HGadget
  getMemory (HGadget m)                           = m
  apply g                                         = applyGad g (salsa20 12)

-- | Reference Gadget instance for Salsa20/12 with 32 Byte KEY
instance Gadget (HGadget (Salsa20 R12 KEY256)) where
  type PrimitiveOf (HGadget (Salsa20 R12 KEY256)) = Salsa20 R12 KEY256
  type MemoryOf (HGadget (Salsa20 R12 KEY256))    = SalsaMem KEY256
  newGadgetWithMemory                             = return . HGadget
  getMemory (HGadget m)                           = m
  apply g                                         = applyGad g (salsa20 12)

-- | CPortable Gadget instance for Salsa20/12 with 16 Byte KEY
instance Gadget (CGadget (Salsa20 R12 KEY128)) where
  type PrimitiveOf (CGadget (Salsa20 R12 KEY128)) = Salsa20 R12 KEY128
  type MemoryOf (CGadget (Salsa20 R12 KEY128))    = SalsaMem KEY128
  newGadgetWithMemory                             = return . CGadget
  getMemory (CGadget m)                           = m
  apply                                           = applyCGad c_salsa20_12

-- | CPortable Gadget instance for Salsa20/12 with 32 Byte KEY
instance Gadget (CGadget (Salsa20 R12 KEY256)) where
  type PrimitiveOf (CGadget (Salsa20 R12 KEY256)) = Salsa20 R12 KEY256
  type MemoryOf (CGadget (Salsa20 R12 KEY256))    = SalsaMem KEY256
  newGadgetWithMemory                             = return . CGadget
  getMemory (CGadget m)                           = m
  apply                                           = applyCGad c_salsa20_12


----------------------------- Salsa 20/8------------ ---------------------------

-- | Reference Gadget instance for Salsa20/8 with 16 Byte KEY
instance Gadget (HGadget (Salsa20 R8 KEY128)) where
  type PrimitiveOf (HGadget (Salsa20 R8 KEY128)) = Salsa20 R8 KEY128
  type MemoryOf (HGadget (Salsa20 R8 KEY128))    = SalsaMem KEY128
  newGadgetWithMemory                            = return . HGadget
  getMemory (HGadget m)                          = m
  apply g                                        = applyGad g (salsa20 8)

-- | Reference Gadget instance for Salsa20/8 with 32 Byte KEY
instance Gadget (HGadget (Salsa20 R8 KEY256)) where
  type PrimitiveOf (HGadget (Salsa20 R8 KEY256)) = Salsa20 R8 KEY256
  type MemoryOf (HGadget (Salsa20 R8 KEY256))    = SalsaMem KEY256
  newGadgetWithMemory                            = return . HGadget
  getMemory (HGadget m)                          = m
  apply g                                        = applyGad g (salsa20 8)

-- | CPortable Gadget instance for Salsa20/8 with 16 Byte KEY
instance Gadget (CGadget (Salsa20 R8 KEY128)) where
  type PrimitiveOf (CGadget (Salsa20 R8 KEY128)) = Salsa20 R8 KEY128
  type MemoryOf (CGadget (Salsa20 R8 KEY128))    = SalsaMem KEY128
  newGadgetWithMemory                            = return . CGadget
  getMemory (CGadget m)                          = m
  apply                                          = applyCGad c_salsa20_8


-- | CPortable Gadget instance for Salsa20/8 with 32 Byte KEY
instance Gadget (CGadget (Salsa20 R8 KEY256)) where
  type PrimitiveOf (CGadget (Salsa20 R8 KEY256)) = Salsa20 R8 KEY256
  type MemoryOf (CGadget (Salsa20 R8 KEY256))    = SalsaMem KEY256
  newGadgetWithMemory                            = return . CGadget
  getMemory (CGadget m)                          = m
  apply                                          = applyCGad c_salsa20_8


applyGad :: (Integral i, Gadget (HGadget t), MemoryOf (HGadget t) ~ SalsaMem k)
            => HGadget t -> (Matrix -> Matrix) -> i -> CryptoPtr -> IO ()
applyGad g@(HGadget (SalsaMem mc)) with n cptr = do
    state <- cellPeek mc
    (newstate,restptr) <- foldM moveAndHash (state,cptr) [1..nblks]
    cellPoke mc =<< restOfblock newstate restptr
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

applyCGad :: (LengthUnit s, MemoryOf (CGadget t) ~ SalsaMem k)
             => (CryptoPtr -> x -> BYTES Int -> IO b) -> CGadget t -> s -> x -> IO b
applyCGad with (CGadget (SalsaMem mc)) n cptr = withCell mc go
  where
    go mptr = with mptr cptr (atMost n)
{-# INLINE applyCGad #-}

instance CryptoPrimitive (Salsa20 R20 KEY128) where
  type Recommended (Salsa20 R20 KEY128) = CGadget (Salsa20 R20 KEY128)
  type Reference (Salsa20 R20 KEY128) = HGadget (Salsa20 R20 KEY128)

instance CryptoPrimitive (Salsa20 R20 KEY256) where
  type Recommended (Salsa20 R20 KEY256) = CGadget (Salsa20 R20 KEY256)
  type Reference (Salsa20 R20 KEY256) = HGadget (Salsa20 R20 KEY256)

instance CryptoPrimitive (Salsa20 R12 KEY128) where
  type Recommended (Salsa20 R12 KEY128) = CGadget (Salsa20 R12 KEY128)
  type Reference (Salsa20 R12 KEY128) = HGadget (Salsa20 R12 KEY128)

instance CryptoPrimitive (Salsa20 R12 KEY256) where
  type Recommended (Salsa20 R12 KEY256) = CGadget (Salsa20 R12 KEY256)
  type Reference (Salsa20 R12 KEY256) = HGadget (Salsa20 R12 KEY256)

instance CryptoPrimitive (Salsa20 R8 KEY128) where
  type Recommended (Salsa20 R8 KEY128) = CGadget (Salsa20 R8 KEY128)
  type Reference (Salsa20 R8 KEY128) = HGadget (Salsa20 R8 KEY128)

instance CryptoPrimitive (Salsa20 R8 KEY256) where
  type Recommended (Salsa20 R8 KEY256) = CGadget (Salsa20 R8 KEY256)
  type Reference (Salsa20 R8 KEY256) = HGadget (Salsa20 R8 KEY256)

instance StreamGadget (CGadget (Salsa20 R20 KEY128))
instance StreamGadget (CGadget (Salsa20 R20 KEY256))
instance StreamGadget (HGadget (Salsa20 R20 KEY128))
instance StreamGadget (HGadget (Salsa20 R20 KEY256))

instance StreamGadget (CGadget (Salsa20 R12 KEY128))
instance StreamGadget (CGadget (Salsa20 R12 KEY256))
instance StreamGadget (HGadget (Salsa20 R12 KEY128))
instance StreamGadget (HGadget (Salsa20 R12 KEY256))

instance StreamGadget (CGadget (Salsa20 R8 KEY128))
instance StreamGadget (CGadget (Salsa20 R8 KEY256))
instance StreamGadget (HGadget (Salsa20 R8 KEY128))
instance StreamGadget (HGadget (Salsa20 R8 KEY256))


instance CryptoInverse (CGadget (Salsa20 R20 KEY128)) where
  type Inverse (CGadget (Salsa20 R20 KEY128)) = CGadget (Salsa20 R20 KEY128)

instance CryptoInverse (CGadget (Salsa20 R20 KEY256)) where
  type Inverse (CGadget (Salsa20 R20 KEY256)) = CGadget (Salsa20 R20 KEY256)

instance CryptoInverse (HGadget (Salsa20 R20 KEY128)) where
  type Inverse (HGadget (Salsa20 R20 KEY128)) = HGadget (Salsa20 R20 KEY128)

instance CryptoInverse (HGadget (Salsa20 R20 KEY256)) where
  type Inverse (HGadget (Salsa20 R20 KEY256)) = HGadget (Salsa20 R20 KEY256)


instance CryptoInverse (CGadget (Salsa20 R12 KEY128)) where
  type Inverse (CGadget (Salsa20 R12 KEY128)) = CGadget (Salsa20 R12 KEY128)

instance CryptoInverse (CGadget (Salsa20 R12 KEY256)) where
  type Inverse (CGadget (Salsa20 R12 KEY256)) = CGadget (Salsa20 R12 KEY256)

instance CryptoInverse (HGadget (Salsa20 R12 KEY128)) where
  type Inverse (HGadget (Salsa20 R12 KEY128)) = HGadget (Salsa20 R12 KEY128)

instance CryptoInverse (HGadget (Salsa20 R12 KEY256)) where
  type Inverse (HGadget (Salsa20 R12 KEY256)) = HGadget (Salsa20 R12 KEY256)


instance CryptoInverse (CGadget (Salsa20 R8 KEY128)) where
  type Inverse (CGadget (Salsa20 R8 KEY128)) = CGadget (Salsa20 R8 KEY128)

instance CryptoInverse (CGadget (Salsa20 R8 KEY256)) where
  type Inverse (CGadget (Salsa20 R8 KEY256)) = CGadget (Salsa20 R8 KEY256)

instance CryptoInverse (HGadget (Salsa20 R8 KEY128)) where
  type Inverse (HGadget (Salsa20 R8 KEY128)) = HGadget (Salsa20 R8 KEY128)

instance CryptoInverse (HGadget (Salsa20 R8 KEY256)) where
  type Inverse (HGadget (Salsa20 R8 KEY256)) = HGadget (Salsa20 R8 KEY256)

instance Cipher (Salsa20 r k)
