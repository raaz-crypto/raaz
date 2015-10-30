{- |

This module provides required instances for Salsa20 Cipher.

-}
{-# LANGUAGE TypeFamilies                  #-}
{-# LANGUAGE FlexibleInstances             #-}
{-# LANGUAGE FlexibleContexts              #-}
{-# LANGUAGE ScopedTypeVariables           #-}
{-# LANGUAGE DataKinds                     #-}
{-# LANGUAGE ForeignFunctionInterface      #-}
{-# OPTIONS_GHC -fno-warn-orphans          #-}
{-# CFILES raaz/cipher/cportable/salsa20.c #-}

module Raaz.Cipher.Salsa20.Instances
       ( CSalsa20Gadget, HSalsa20Gadget
       ) where

import Control.Monad
import Data.Bits
import Data.ByteString                    (unpack)
import Data.Word
import Foreign.Ptr
import Foreign.Storable

import Raaz.Core.Encode
import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Cipher
import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Cipher.Salsa20.Block.Internal
import Raaz.Cipher.Salsa20.Block.Type
import Raaz.Cipher.Salsa20.Internal

-- | Primitive instance for Salsa20 where Context includes the Key,
-- Nonce (8 Byte) and Counter (8 Byte).
instance Primitive (Salsa20 r k) where
  blockSize _            = BYTES 1
  {-# INLINE blockSize #-}
  type Key (Salsa20 r k) = (k, Nonce)

----------------------------- Gadgets for Salsa20 ------------ --------

-- | CGadget for Salsa20.
type CSalsa20Gadget r k = CGadget (Salsa20 r k) (MemoryCell Matrix)

-- | HGadget for Salsa20
type HSalsa20Gadget r k = HGadget (Salsa20 r k) (MemoryCell Matrix)

instance InitializableMemory (CSalsa20Gadget r KEY128) where
  type IV (CSalsa20Gadget r KEY128) = (KEY128, Nonce)

  initializeMemory (CGadget cell) (k,n) = cExpand128 cell k n counter0

instance InitializableMemory (HSalsa20Gadget r KEY128) where
  type IV (HSalsa20Gadget r KEY128) = (KEY128, Nonce)

  initializeMemory (HGadget cell) (k,n) = cExpand128 cell k n counter0

instance InitializableMemory (CSalsa20Gadget r KEY256) where
  type IV (CSalsa20Gadget r KEY256) = (KEY256, Nonce)

  initializeMemory (CGadget cell) (k,n) = cExpand256 cell k n counter0

instance InitializableMemory (HSalsa20Gadget r KEY256) where
  type IV (HSalsa20Gadget r KEY256) = (KEY256, Nonce)

  initializeMemory (HGadget cell) (k,n) = cExpand256 cell k n counter0

counter0 :: Counter
counter0 = Counter (SplitWord64 0 0)

------------------- Gadget instansces. -------------------------------

-- | Reference Gadget instance for Salsa20/20 with 16 Byte KEY
instance Gadget (HSalsa20Gadget R20 KEY128) where
  type PrimitiveOf (HSalsa20Gadget R20 KEY128)  = Salsa20 R20 KEY128
  apply g                                       = applyGad g (salsa20 20)

-- | Reference Gadget instance for Salsa20/20 with 32 Byte KEY
instance Gadget (HSalsa20Gadget R20 KEY256) where
  type PrimitiveOf (HSalsa20Gadget R20 KEY256) = Salsa20 R20 KEY256
  apply g                                      = applyGad g (salsa20 20)

-- | CPortable Gadget instance for Salsa20/20 with 16 Byte KEY
instance Gadget (CSalsa20Gadget R20 KEY128) where
  type PrimitiveOf (CSalsa20Gadget R20 KEY128) = Salsa20 R20 KEY128
  apply                                        = applyCGad c_salsa20_20

-- | CPortable Gadget instance for Salsa20/20 with 32 Byte KEY
instance Gadget (CSalsa20Gadget R20 KEY256) where
  type PrimitiveOf (CSalsa20Gadget R20 KEY256) = Salsa20 R20 KEY256
  apply                                        = applyCGad c_salsa20_20


----------------------------- Salsa 20/12------------ ---------------------------

-- | Reference Gadget instance for Salsa20/12 with 16 Byte KEY
instance Gadget (HSalsa20Gadget R12 KEY128) where
  type PrimitiveOf (HSalsa20Gadget R12 KEY128) = Salsa20 R12 KEY128
  apply g                                         = applyGad g (salsa20 12)

-- | Reference Gadget instance for Salsa20/12 with 32 Byte KEY
instance Gadget (HSalsa20Gadget R12 KEY256) where
  type PrimitiveOf (HSalsa20Gadget R12 KEY256) = Salsa20 R12 KEY256
  apply g                                      = applyGad g (salsa20 12)

-- | CPortable Gadget instance for Salsa20/12 with 16 Byte KEY
instance Gadget (CSalsa20Gadget R12 KEY128) where
  type PrimitiveOf (CSalsa20Gadget R12 KEY128) = Salsa20 R12 KEY128
  apply                                        = applyCGad c_salsa20_12

-- | CPortable Gadget instance for Salsa20/12 with 32 Byte KEY
instance Gadget (CSalsa20Gadget R12 KEY256) where
  type PrimitiveOf (CSalsa20Gadget R12 KEY256) = Salsa20 R12 KEY256
  apply                                        = applyCGad c_salsa20_12


----------------------------- Salsa 20/8------------ ---------------------------

-- | Reference Gadget instance for Salsa20/8 with 16 Byte KEY
instance Gadget (HSalsa20Gadget R8 KEY128) where
  type PrimitiveOf (HSalsa20Gadget R8 KEY128) = Salsa20 R8 KEY128
  apply g                                        = applyGad g (salsa20 8)

-- | Reference Gadget instance for Salsa20/8 with 32 Byte KEY
instance Gadget (HSalsa20Gadget R8 KEY256) where
  type PrimitiveOf (HSalsa20Gadget R8 KEY256) = Salsa20 R8 KEY256
  apply g                                        = applyGad g (salsa20 8)

-- | CPortable Gadget instance for Salsa20/8 with 16 Byte KEY
instance Gadget (CSalsa20Gadget R8 KEY128) where
  type PrimitiveOf (CSalsa20Gadget R8 KEY128) = Salsa20 R8 KEY128
  apply                                          = applyCGad c_salsa20_8


-- | CPortable Gadget instance for Salsa20/8 with 32 Byte KEY
instance Gadget (CSalsa20Gadget R8 KEY256) where
  type PrimitiveOf (CSalsa20Gadget R8 KEY256) = Salsa20 R8 KEY256
  apply                                       = applyCGad c_salsa20_8


applyGad :: (Integral i, Gadget (HSalsa20Gadget r k))
            => HSalsa20Gadget r k -> (Matrix -> Matrix) -> i -> CryptoPtr -> IO ()
applyGad g@(HGadget mc) with n cptr = do
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

applyCGad :: (LengthUnit s, Gadget (CSalsa20Gadget r k))
             => (CryptoPtr -> x -> BYTES Int -> IO b) -> CSalsa20Gadget r k -> s -> x -> IO b
applyCGad with (CGadget mc) n cptr = withCell mc go
  where
    go mptr = with mptr cptr (atMost n)
{-# INLINE applyCGad #-}

instance CryptoPrimitive (Salsa20 R20 KEY128) where
  type Recommended (Salsa20 R20 KEY128) = CSalsa20Gadget R20 KEY128
  type Reference (Salsa20 R20 KEY128)   = HSalsa20Gadget R20 KEY128

instance CryptoPrimitive (Salsa20 R20 KEY256) where
  type Recommended (Salsa20 R20 KEY256) = CSalsa20Gadget R20 KEY256
  type Reference (Salsa20 R20 KEY256) = HSalsa20Gadget R20 KEY256

instance CryptoPrimitive (Salsa20 R12 KEY128) where
  type Recommended (Salsa20 R12 KEY128) = CSalsa20Gadget R12 KEY128
  type Reference (Salsa20 R12 KEY128)   = HSalsa20Gadget R12 KEY128

instance CryptoPrimitive (Salsa20 R12 KEY256) where
  type Recommended (Salsa20 R12 KEY256) = CSalsa20Gadget R12 KEY256
  type Reference (Salsa20 R12 KEY256)   = HSalsa20Gadget R12 KEY256

instance CryptoPrimitive (Salsa20 R8 KEY128) where
  type Recommended (Salsa20 R8 KEY128) = CSalsa20Gadget R8 KEY128
  type Reference (Salsa20 R8 KEY128)   = HSalsa20Gadget R8 KEY128

instance CryptoPrimitive (Salsa20 R8 KEY256) where
  type Recommended (Salsa20 R8 KEY256) = CSalsa20Gadget R8 KEY256
  type Reference (Salsa20 R8 KEY256)   = HSalsa20Gadget R8 KEY256

instance StreamGadget (CSalsa20Gadget R20 KEY128)
instance StreamGadget (CSalsa20Gadget R20 KEY256)
instance StreamGadget (HSalsa20Gadget R20 KEY128)
instance StreamGadget (HSalsa20Gadget R20 KEY256)

instance StreamGadget (CSalsa20Gadget R12 KEY128)
instance StreamGadget (CSalsa20Gadget R12 KEY256)
instance StreamGadget (HSalsa20Gadget R12 KEY128)
instance StreamGadget (HSalsa20Gadget R12 KEY256)

instance StreamGadget (CSalsa20Gadget R8 KEY128)
instance StreamGadget (CSalsa20Gadget R8 KEY256)
instance StreamGadget (HSalsa20Gadget R8 KEY128)
instance StreamGadget (HSalsa20Gadget R8 KEY256)


instance CryptoInverse (CSalsa20Gadget R20 KEY128) where
  type Inverse (CSalsa20Gadget R20 KEY128) = CSalsa20Gadget R20 KEY128

instance CryptoInverse (CSalsa20Gadget R20 KEY256) where
  type Inverse (CSalsa20Gadget R20 KEY256) = CSalsa20Gadget R20 KEY256

instance CryptoInverse (HSalsa20Gadget R20 KEY128) where
  type Inverse (HSalsa20Gadget R20 KEY128) = HSalsa20Gadget R20 KEY128

instance CryptoInverse (HSalsa20Gadget R20 KEY256) where
  type Inverse (HSalsa20Gadget R20 KEY256) = HSalsa20Gadget R20 KEY256


instance CryptoInverse (CSalsa20Gadget R12 KEY128) where
  type Inverse (CSalsa20Gadget R12 KEY128) = CSalsa20Gadget R12 KEY128

instance CryptoInverse (CSalsa20Gadget R12 KEY256) where
  type Inverse (CSalsa20Gadget R12 KEY256) = CSalsa20Gadget R12 KEY256

instance CryptoInverse (HSalsa20Gadget R12 KEY128) where
  type Inverse (HSalsa20Gadget R12 KEY128) = HSalsa20Gadget R12 KEY128

instance CryptoInverse (HSalsa20Gadget R12 KEY256) where
  type Inverse (HSalsa20Gadget R12 KEY256) = HSalsa20Gadget R12 KEY256


instance CryptoInverse (CSalsa20Gadget R8 KEY128) where
  type Inverse (CSalsa20Gadget R8 KEY128) = CSalsa20Gadget R8 KEY128

instance CryptoInverse (CSalsa20Gadget R8 KEY256) where
  type Inverse (CSalsa20Gadget R8 KEY256) = CSalsa20Gadget R8 KEY256

instance CryptoInverse (HSalsa20Gadget R8 KEY128) where
  type Inverse (HSalsa20Gadget R8 KEY128) = HSalsa20Gadget R8 KEY128

instance CryptoInverse (HSalsa20Gadget R8 KEY256) where
  type Inverse (HSalsa20Gadget R8 KEY256) = HSalsa20Gadget R8 KEY256

instance Cipher (Salsa20 r k)

------------------  Foreign function calls and wrappers -------------------

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



-- | SECURITY LOOPHOLE. Read similar function in AES for description
-- of the problem.
cExpansionWith :: EndianStore k
                => (CryptoPtr -> CryptoPtr -> IO ())
                -> MemoryCell Matrix
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

cExpand128 :: MemoryCell Matrix -> KEY128 -> Nonce -> Counter -> IO ()
cExpand128 = cExpansionWith c_expand128
{-# INLINE cExpand128 #-}

cExpand256 :: MemoryCell Matrix -> KEY256 -> Nonce -> Counter -> IO ()
cExpand256 = cExpansionWith c_expand256
{-# INLINE cExpand256 #-}
