{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Cipher.AES.Ref.Type
       ( SplitWord32(..)
       , STATE(..)
       , KEY128(..)
       , Expanded128(..)
       , KEY192(..)
       , Expanded192(..)
       , KEY256(..)
       , Expanded256(..)
       , xor'
       , fromByteString
       , incrState
       , stateToList
       )where

import Control.Applicative ((<$>), (<*>))
import Data.Bits           (xor, (.|.),Bits(..))
import Data.ByteString     (ByteString)
import Data.Word
import Data.Typeable       (Typeable)
import Foreign.Storable    (sizeOf,Storable(..))
import Numeric             (showHex)
import System.IO.Unsafe    (unsafePerformIO)

import Raaz.ByteSource
import Raaz.Memory
import Raaz.Types


data SplitWord32 = SplitWord32 {-# UNPACK #-} !Word8
                               {-# UNPACK #-} !Word8
                               {-# UNPACK #-} !Word8
                               {-# UNPACK #-} !Word8
                 deriving (Typeable)

-- | Special show instance to display in hex instead of decimal
instance Show SplitWord32 where
  show (SplitWord32 w1 w2 w3 w4) =   showHex w1
                                   . showHex w2
                                   . showHex w3
                                   . showHex w4
                                   $ ""

-- | AES State
data STATE = STATE {-# UNPACK #-} !SplitWord32
                   {-# UNPACK #-} !SplitWord32
                   {-# UNPACK #-} !SplitWord32
                   {-# UNPACK #-} !SplitWord32
         deriving (Show, Typeable)

-- | 128 Bit Key
data KEY128 = KEY128 {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
         deriving (Show, Typeable)

-- | 192 Bit Key
data KEY192 = KEY192 {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
         deriving (Show, Typeable)

-- | 256 Bit Key
data KEY256 = KEY256 {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
                     {-# UNPACK #-} !SplitWord32
         deriving (Show, Typeable)

-- | Incrments the STATE considering it to be a byte string. Used in
-- AES CTR mode.
incrState :: STATE -> STATE
incrState (STATE (SplitWord32 w00 w01 w02 w03)
                 (SplitWord32 w10 w11 w12 w13)
                 (SplitWord32 w20 w21 w22 w23)
                 (SplitWord32 w30 w31 w32 w33)) =
           STATE (SplitWord32 r00 r01 r02 r03)
                 (SplitWord32 r10 r11 r12 r13)
                 (SplitWord32 r20 r21 r22 r23)
                 (SplitWord32 r30 r31 r32 r33)
  where
    ifincr prev this = if prev == 0 then this + 1 else this
    r33 = w33 + 1
    r32 = ifincr r33 w32
    r31 = ifincr r32 w31
    r30 = ifincr r31 w30
    r23 = ifincr r30 w23
    r22 = ifincr r23 w22
    r21 = ifincr r22 w21
    r20 = ifincr r21 w20
    r13 = ifincr r20 w13
    r12 = ifincr r13 w12
    r11 = ifincr r12 w11
    r10 = ifincr r11 w10
    r03 = ifincr r10 w03
    r02 = ifincr r03 w02
    r01 = ifincr r02 w01
    r00 = ifincr r01 w00


stateToList :: STATE -> [Word8]
stateToList (STATE sp0 sp1 sp2 sp3) = concatMap swToList [sp0,sp1,sp2,sp3]
  where
    swToList :: SplitWord32 -> [Word8]
    swToList (SplitWord32 w0 w1 w2 w3) = [w0,w1,w2,w3]

-- | Get the value from the bytestring. Used internally for keys only.
fromByteString :: (Storable k) => ByteString -> k
fromByteString src = unsafePerformIO $ using undefined
  where
    using :: Storable k => k -> IO k
    using k = do
      m <- newMemory
      withCell m doStuff
      k' <- cellLoad m
      return k'
      where
        size = sizeOf k
        doStuff cptr = withFillResult (const $ return ()) errorKey
                       =<< fillBytes (BYTES size) src cptr
          where
            errorKey = error "Unable to fill key with available data"

-- | Expanded Key for 128 Bit Key
data Expanded128 =
    Expanded128 {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
           deriving (Show,Typeable)

-- | Expanded Key for 192 Bit Key
data Expanded192 =
    Expanded192 {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
        deriving (Show, Typeable)

-- | Expanded Key for 256 Bit Key
data Expanded256 =
    Expanded256 {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
                {-# UNPACK #-} !STATE
        deriving (Show, Typeable)

-- | Timing independed equality testing for SplitWord32
instance Eq SplitWord32 where
  (==) (SplitWord32 r0 r1 r2 r3)
       (SplitWord32 s0 s1 s2 s3) =  xor r0 s0
                                .|. xor r1 s1
                                .|. xor r2 s2
                                .|. xor r3 s3
                                == 0

-- | Timing independent equality testing for STATE
instance Eq STATE where
  (==) (STATE r0 r1 r2 r3)
       (STATE s0 s1 s2 s3) =  xor' r0 s0
                          .||. xor' r1 s1
                          .||. xor' r2 s2
                          .||. xor' r3 s3
                          == (SplitWord32 0 0 0 0)

-- | Timing independent equality testing for KEY128
instance Eq KEY128 where
  (==) (KEY128 r0 r1 r2 r3)
       (KEY128 s0 s1 s2 s3) =   xor' r0 s0
                           .||. xor' r1 s1
                           .||. xor' r2 s2
                           .||. xor' r3 s3
                           == (SplitWord32 0 0 0 0)

-- | Timing independent equality testing for KEY192
instance Eq KEY192 where
  (==) (KEY192 r0 r1 r2 r3 r4 r5)
       (KEY192 s0 s1 s2 s3 s4 s5) =   xor' r0 s0
                                 .||. xor' r1 s1
                                 .||. xor' r2 s2
                                 .||. xor' r3 s3
                                 .||. xor' r4 s4
                                 .||. xor' r5 s5
                                 == (SplitWord32 0 0 0 0)

-- | Timing independent equality testing for KEY256
instance Eq KEY256 where
  (==) (KEY256 r0 r1 r2 r3 r4 r5 r6 r7)
       (KEY256 s0 s1 s2 s3 s4 s5 s6 s7) =   xor' r0 s0
                                       .||. xor' r1 s1
                                       .||. xor' r2 s2
                                       .||. xor' r3 s3
                                       .||. xor' r4 s4
                                       .||. xor' r5 s5
                                       .||. xor' r6 s6
                                       .||. xor' r7 s7
                                       == (SplitWord32 0 0 0 0)

xor' :: SplitWord32 -> SplitWord32 -> SplitWord32
xor' (SplitWord32 r0 r1 r2 r3)
     (SplitWord32 s0 s1 s2 s3) = SplitWord32 (r0 `xor` s0)
                                             (r1 `xor` s1)
                                             (r2 `xor` s2)
                                             (r3 `xor` s3)
{-# INLINE xor' #-}

(.||.) :: SplitWord32 -> SplitWord32 -> SplitWord32
(.||.) (SplitWord32 r0 r1 r2 r3)
       (SplitWord32 s0 s1 s2 s3) = SplitWord32 (r0 .|. s0)
                                               (r1 .|. s1)
                                               (r2 .|. s2)
                                               (r3 .|. s3)
{-# INLINE (.||.) #-}

instance Storable SplitWord32 where
  sizeOf    _ = 4 * sizeOf (undefined :: Word8)
  alignment _ = alignment  (undefined :: CryptoAlign)
  peekByteOff ptr pos = SplitWord32 <$> peekByteOff ptr pos0
                                    <*> peekByteOff ptr pos1
                                    <*> peekByteOff ptr pos2
                                    <*> peekByteOff ptr pos3
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          offset = sizeOf (undefined:: Word8)
  pokeByteOff ptr pos (SplitWord32 r0 r1 r2 r3)
      =  pokeByteOff ptr pos0 r0
      >> pokeByteOff ptr pos1 r1
      >> pokeByteOff ptr pos2 r2
      >> pokeByteOff ptr pos3 r3
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          offset = sizeOf (undefined:: Word8)

instance Storable STATE where
  sizeOf    _ = 4 * sizeOf (undefined :: SplitWord32)
  alignment _ = alignment  (undefined :: SplitWord32)
  peekByteOff ptr pos = STATE <$> peekByteOff ptr pos0
                              <*> peekByteOff ptr pos1
                              <*> peekByteOff ptr pos2
                              <*> peekByteOff ptr pos3
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          offset = sizeOf (undefined:: SplitWord32)
  pokeByteOff ptr pos (STATE r0 r1 r2 r3)
      =  pokeByteOff ptr pos0 r0
      >> pokeByteOff ptr pos1 r1
      >> pokeByteOff ptr pos2 r2
      >> pokeByteOff ptr pos3 r3
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          offset = sizeOf (undefined:: SplitWord32)

instance Storable KEY128 where
  sizeOf    _ = 4 * sizeOf (undefined :: SplitWord32)
  alignment _ = alignment  (undefined :: SplitWord32)
  peekByteOff ptr pos = KEY128 <$> peekByteOff ptr pos0
                               <*> peekByteOff ptr pos1
                               <*> peekByteOff ptr pos2
                               <*> peekByteOff ptr pos3
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          offset = sizeOf (undefined:: SplitWord32)
  pokeByteOff ptr pos (KEY128 h0 h1 h2 h3)
      =  pokeByteOff ptr pos0 h0
      >> pokeByteOff ptr pos1 h1
      >> pokeByteOff ptr pos2 h2
      >> pokeByteOff ptr pos3 h3
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          offset = sizeOf (undefined:: SplitWord32)

instance Storable KEY192 where
  sizeOf    _ = 6 * sizeOf (undefined :: SplitWord32)
  alignment _ = alignment  (undefined :: SplitWord32)
  peekByteOff ptr pos = KEY192 <$> peekByteOff ptr pos0
                               <*> peekByteOff ptr pos1
                               <*> peekByteOff ptr pos2
                               <*> peekByteOff ptr pos3
                               <*> peekByteOff ptr pos4
                               <*> peekByteOff ptr pos5
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          offset = sizeOf (undefined:: SplitWord32)

  pokeByteOff ptr pos (KEY192 h0 h1 h2 h3 h4 h5)
      =  pokeByteOff ptr pos0 h0
      >> pokeByteOff ptr pos1 h1
      >> pokeByteOff ptr pos2 h2
      >> pokeByteOff ptr pos3 h3
      >> pokeByteOff ptr pos4 h4
      >> pokeByteOff ptr pos5 h5
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          offset = sizeOf (undefined:: SplitWord32)

instance Storable KEY256 where
  sizeOf    _ = 8 * sizeOf (undefined :: SplitWord32)
  alignment _ = alignment  (undefined :: SplitWord32)
  peekByteOff ptr pos = KEY256 <$> peekByteOff ptr pos0
                               <*> peekByteOff ptr pos1
                               <*> peekByteOff ptr pos2
                               <*> peekByteOff ptr pos3
                               <*> peekByteOff ptr pos4
                               <*> peekByteOff ptr pos5
                               <*> peekByteOff ptr pos6
                               <*> peekByteOff ptr pos7
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          pos6   = pos5 + offset
          pos7   = pos6 + offset
          offset = sizeOf (undefined:: SplitWord32)

  pokeByteOff ptr pos (KEY256 h0 h1 h2 h3 h4 h5 h6 h7)
      =  pokeByteOff ptr pos0 h0
      >> pokeByteOff ptr pos1 h1
      >> pokeByteOff ptr pos2 h2
      >> pokeByteOff ptr pos3 h3
      >> pokeByteOff ptr pos4 h4
      >> pokeByteOff ptr pos5 h5
      >> pokeByteOff ptr pos6 h6
      >> pokeByteOff ptr pos7 h7
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          pos6   = pos5 + offset
          pos7   = pos6 + offset
          offset = sizeOf (undefined:: SplitWord32)


instance Storable Expanded128 where
  sizeOf    _ = 11 * sizeOf (undefined :: STATE)
  alignment _ = alignment  (undefined :: STATE)
  peekByteOff ptr pos = Expanded128 <$> peekByteOff ptr pos0
                                    <*> peekByteOff ptr pos1
                                    <*> peekByteOff ptr pos2
                                    <*> peekByteOff ptr pos3
                                    <*> peekByteOff ptr pos4
                                    <*> peekByteOff ptr pos5
                                    <*> peekByteOff ptr pos6
                                    <*> peekByteOff ptr pos7
                                    <*> peekByteOff ptr pos8
                                    <*> peekByteOff ptr pos9
                                    <*> peekByteOff ptr pos10
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          pos6   = pos5 + offset
          pos7   = pos6 + offset
          pos8   = pos7 + offset
          pos9   = pos8 + offset
          pos10   = pos9 + offset
          offset = sizeOf (undefined:: STATE)

  pokeByteOff ptr pos (Expanded128 h0 h1 h2 h3 h4 h5 h6 h7 h8 h9 h10)
      =  pokeByteOff ptr pos0 h0
      >> pokeByteOff ptr pos1 h1
      >> pokeByteOff ptr pos2 h2
      >> pokeByteOff ptr pos3 h3
      >> pokeByteOff ptr pos4 h4
      >> pokeByteOff ptr pos5 h5
      >> pokeByteOff ptr pos6 h6
      >> pokeByteOff ptr pos7 h7
      >> pokeByteOff ptr pos8 h8
      >> pokeByteOff ptr pos9 h9
      >> pokeByteOff ptr pos10 h10
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          pos6   = pos5 + offset
          pos7   = pos6 + offset
          pos8   = pos7 + offset
          pos9   = pos8 + offset
          pos10   = pos9 + offset
          offset = sizeOf (undefined:: STATE)

instance Storable Expanded192 where
  sizeOf    _ = 13 * sizeOf (undefined :: STATE)
  alignment _ = alignment  (undefined :: STATE)
  peekByteOff ptr pos = Expanded192 <$> peekByteOff ptr pos0
                                    <*> peekByteOff ptr pos1
                                    <*> peekByteOff ptr pos2
                                    <*> peekByteOff ptr pos3
                                    <*> peekByteOff ptr pos4
                                    <*> peekByteOff ptr pos5
                                    <*> peekByteOff ptr pos6
                                    <*> peekByteOff ptr pos7
                                    <*> peekByteOff ptr pos8
                                    <*> peekByteOff ptr pos9
                                    <*> peekByteOff ptr pos10
                                    <*> peekByteOff ptr pos11
                                    <*> peekByteOff ptr pos12
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          pos6   = pos5 + offset
          pos7   = pos6 + offset
          pos8   = pos7 + offset
          pos9   = pos8 + offset
          pos10   = pos9 + offset
          pos11   = pos10 + offset
          pos12   = pos11 + offset
          offset = sizeOf (undefined:: STATE)

  pokeByteOff ptr pos (Expanded192 h0 h1 h2 h3 h4 h5 h6 h7 h8 h9 h10
                       h11 h12)
      =  pokeByteOff ptr pos0 h0
      >> pokeByteOff ptr pos1 h1
      >> pokeByteOff ptr pos2 h2
      >> pokeByteOff ptr pos3 h3
      >> pokeByteOff ptr pos4 h4
      >> pokeByteOff ptr pos5 h5
      >> pokeByteOff ptr pos6 h6
      >> pokeByteOff ptr pos7 h7
      >> pokeByteOff ptr pos8 h8
      >> pokeByteOff ptr pos9 h9
      >> pokeByteOff ptr pos10 h10
      >> pokeByteOff ptr pos11 h11
      >> pokeByteOff ptr pos12 h12
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          pos6   = pos5 + offset
          pos7   = pos6 + offset
          pos8   = pos7 + offset
          pos9   = pos8 + offset
          pos10   = pos9 + offset
          pos11   = pos10 + offset
          pos12   = pos11 + offset
          offset = sizeOf (undefined:: STATE)

instance Storable Expanded256 where
  sizeOf    _ = 15 * sizeOf (undefined :: STATE)
  alignment _ = alignment  (undefined :: STATE)
  peekByteOff ptr pos = Expanded256 <$> peekByteOff ptr pos0
                                    <*> peekByteOff ptr pos1
                                    <*> peekByteOff ptr pos2
                                    <*> peekByteOff ptr pos3
                                    <*> peekByteOff ptr pos4
                                    <*> peekByteOff ptr pos5
                                    <*> peekByteOff ptr pos6
                                    <*> peekByteOff ptr pos7
                                    <*> peekByteOff ptr pos8
                                    <*> peekByteOff ptr pos9
                                    <*> peekByteOff ptr pos10
                                    <*> peekByteOff ptr pos11
                                    <*> peekByteOff ptr pos12
                                    <*> peekByteOff ptr pos13
                                    <*> peekByteOff ptr pos14
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          pos6   = pos5 + offset
          pos7   = pos6 + offset
          pos8   = pos7 + offset
          pos9   = pos8 + offset
          pos10   = pos9 + offset
          pos11   = pos10 + offset
          pos12   = pos11 + offset
          pos13   = pos12 + offset
          pos14   = pos13 + offset
          offset = sizeOf (undefined:: STATE)

  pokeByteOff ptr pos (Expanded256 h0 h1 h2 h3 h4 h5 h6 h7 h8 h9 h10
                       h11 h12 h13 h14)
      =  pokeByteOff ptr pos0 h0
      >> pokeByteOff ptr pos1 h1
      >> pokeByteOff ptr pos2 h2
      >> pokeByteOff ptr pos3 h3
      >> pokeByteOff ptr pos4 h4
      >> pokeByteOff ptr pos5 h5
      >> pokeByteOff ptr pos6 h6
      >> pokeByteOff ptr pos7 h7
      >> pokeByteOff ptr pos8 h8
      >> pokeByteOff ptr pos9 h9
      >> pokeByteOff ptr pos10 h10
      >> pokeByteOff ptr pos11 h11
      >> pokeByteOff ptr pos12 h12
      >> pokeByteOff ptr pos13 h13
      >> pokeByteOff ptr pos14 h14
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          pos6   = pos5 + offset
          pos7   = pos6 + offset
          pos8   = pos7 + offset
          pos9   = pos8 + offset
          pos10   = pos9 + offset
          pos11   = pos10 + offset
          pos12   = pos11 + offset
          pos13   = pos12 + offset
          pos14   = pos13 + offset
          offset = sizeOf (undefined:: STATE)
