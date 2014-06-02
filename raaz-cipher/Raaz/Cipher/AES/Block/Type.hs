{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DataKinds                  #-}

module Raaz.Cipher.AES.Block.Type
       ( STATE(..)
       , KEY128(..)
       , Expanded128(..)
       , KEY192(..)
       , Expanded192(..)
       , KEY256(..)
       , Expanded256(..)
       , AEScxt(..)
       , incrState
       , fmapState
       , constructWord32BE
       , transpose
       , invTranspose
       )where

import Control.Applicative  ( (<$>), (<*>)         )
import Data.Bits            ( xor, (.|.), Bits(..) )
import Data.Monoid          ( (<>)                 )
import Data.Typeable        ( Typeable             )
import Foreign.Ptr          ( castPtr              )
import Foreign.Storable     ( sizeOf,Storable(..)  )
import Numeric              ( showHex              )

import Raaz.Core.Serialize
import Raaz.Core.Types
import Raaz.Core.Parse.Unsafe
import Raaz.Core.Write.Unsafe

-- | AES State
data STATE = STATE {-# UNPACK #-} !Word32BE
                   {-# UNPACK #-} !Word32BE
                   {-# UNPACK #-} !Word32BE
                   {-# UNPACK #-} !Word32BE
         deriving Typeable

instance Show STATE where
  show (STATE w0 w1 w2 w3) = showString "STATE "
                           . showWord32 w0
                           . showChar ' '
                           . showWord32 w1
                           . showChar ' '
                           . showWord32 w2
                           . showChar ' '
                           $ showWord32 w3 ""

-- | AES Cxt (Used in CBC and CTR mode)
newtype AEScxt = AEScxt STATE
         deriving (Show,Typeable,Eq,Storable)

-- | Incrments the STATE considering it to be a byte string. It is
-- sligthly different because of transposing of data during load and
-- store. Used in AES CTR mode.
incrState :: STATE -> STATE
incrState = transpose . incr . invTranspose
  where
    incr (STATE w0 w1 w2 w3) = STATE r0 r1 r2 r3
      where
        ifincr prev this = if prev == 0 then this + 1 else this
        r3 = w3 + 1
        r2 = ifincr r3 w2
        r1 = ifincr r2 w1
        r0 = ifincr r1 w0

-- | Maps a function over `STATE`.
fmapState :: (Word32BE -> Word32BE) -> STATE -> STATE
fmapState f (STATE s0 s1 s2 s3) = STATE (f s0) (f s1) (f s2) (f s3)

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

-- | Timing independent equality testing for STATE
instance Eq STATE where
  (==) (STATE r0 r1 r2 r3)
       (STATE s0 s1 s2 s3) =  xor r0 s0
                          .|. xor r1 s1
                          .|. xor r2 s2
                          .|. xor r3 s3
                          == 0

parseState :: Parser STATE
parseState = STATE <$> parse
                   <*> parse
                   <*> parse
                   <*> parse

writeState :: STATE -> Write
writeState (STATE s0 s1 s2 s3) = write s0
                              <> write s1
                              <> write s2
                              <> write s3


instance Storable STATE where
  sizeOf    _ = 4 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseState
  poke cptr state = runWrite (castPtr cptr) $ writeState state

instance EndianStore STATE where
  load cptr = runParser cptr (transpose <$> parseState)
  store cptr state = runWrite cptr $ writeState $ invTranspose state

instance CryptoSerialize STATE

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

-- | Constructs a Word32BE from Least significan 8 bits of given 4 words
constructWord32BE :: Word32BE -> Word32BE -> Word32BE -> Word32BE -> Word32BE
constructWord32BE w0 w1 w2 w3 = r3 `xor` r2 `xor` r1 `xor` r0
  where
    mask w = w .&. 0x000000FF
    r3 = mask w3
    r2 = mask w2 `shiftL` 8
    r1 = mask w1 `shiftL` 16
    r0 = mask w0 `shiftL` 24

-- | Transpose of the STATE
transpose :: STATE -> STATE
transpose (STATE w0 w1 w2 w3) =
           STATE (constructWord32BE s00 s01 s02 s03)
                 (constructWord32BE s10 s11 s12 s13)
                 (constructWord32BE s20 s21 s22 s23)
                 (constructWord32BE w0 w1 w2 w3)
  where
    s20 = w0 `shiftR` 8
    s21 = w1 `shiftR` 8
    s22 = w2 `shiftR` 8
    s23 = w3 `shiftR` 8
    s10 = w0 `shiftR` 16
    s11 = w1 `shiftR` 16
    s12 = w2 `shiftR` 16
    s13 = w3 `shiftR` 16
    s00 = w0 `shiftR` 24
    s01 = w1 `shiftR` 24
    s02 = w2 `shiftR` 24
    s03 = w3 `shiftR` 24
{-# INLINE transpose #-}

-- | Reverse of Transpose of STATE
invTranspose :: STATE -> STATE
invTranspose (STATE w0 w1 w2 w3) =
           STATE (constructWord32BE s00 s01 s02 s03)
                 (constructWord32BE s10 s11 s12 s13)
                 (constructWord32BE s20 s21 s22 s23)
                 (constructWord32BE s30 s31 s32 s33)
  where
    s00 = w0 `shiftR` 24
    s10 = w0 `shiftR` 16
    s20 = w0 `shiftR` 8
    s30 = w0
    s01 = w1 `shiftR` 24
    s11 = w1 `shiftR` 16
    s21 = w1 `shiftR` 8
    s31 = w1
    s02 = w2 `shiftR` 24
    s12 = w2 `shiftR` 16
    s22 = w2 `shiftR` 8
    s32 = w2
    s03 = w3 `shiftR` 24
    s13 = w3 `shiftR` 16
    s23 = w3 `shiftR` 8
    s33 = w3

-- | 128 Bit Key
data KEY128 = KEY128 {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
         deriving Typeable

-- | Hexadecimal Show instance
instance Show KEY128 where
  show (KEY128 w0 w1 w2 w3) = showString "KEY128 "
                            . showWord32 w0
                            . showChar ' '
                            . showWord32 w1
                            . showChar ' '
                            . showWord32 w2
                            . showChar ' '
                            $ showWord32 w3 ""

-- | 192 Bit Key
data KEY192 = KEY192 {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
         deriving Typeable

-- | Hexadecimal Show instance
instance Show KEY192 where
  show (KEY192 w0 w1 w2 w3 w4 w5) = showString "KEY192 "
                                  . showWord32 w0
                                  . showChar ' '
                                  . showWord32 w1
                                  . showChar ' '
                                  . showWord32 w2
                                  . showChar ' '
                                  . showWord32 w3
                                  . showChar ' '
                                  . showWord32 w4
                                  . showChar ' '
                                  $ showWord32 w5 ""

-- | 256 Bit Key
data KEY256 = KEY256 {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
         deriving Typeable

-- | Hexadecimal Show instance
instance Show KEY256 where
  show (KEY256 w0 w1 w2 w3 w4 w5 w6 w7) = showString "KEY256 "
                                        . showWord32 w0
                                        . showChar ' '
                                        . showWord32 w1
                                        . showChar ' '
                                        . showWord32 w2
                                        . showChar ' '
                                        . showWord32 w3
                                        . showChar ' '
                                        . showWord32 w4
                                        . showChar ' '
                                        . showWord32 w5
                                        . showChar ' '
                                        . showWord32 w6
                                        . showChar ' '
                                        $ showWord32 w7 ""

-- | Timing independent equality testing for KEY128
instance Eq KEY128 where
  (==) (KEY128 r0 r1 r2 r3)
       (KEY128 s0 s1 s2 s3) =  xor r0 s0
                           .|. xor r1 s1
                           .|. xor r2 s2
                           .|. xor r3 s3
                           == 0

-- | Timing independent equality testing for KEY192
instance Eq KEY192 where
  (==) (KEY192 r0 r1 r2 r3 r4 r5)
       (KEY192 s0 s1 s2 s3 s4 s5) =  xor r0 s0
                                 .|. xor r1 s1
                                 .|. xor r2 s2
                                 .|. xor r3 s3
                                 .|. xor r4 s4
                                 .|. xor r5 s5
                                 == 0

-- | Timing independent equality testing for KEY256
instance Eq KEY256 where
  (==) (KEY256 r0 r1 r2 r3 r4 r5 r6 r7)
       (KEY256 s0 s1 s2 s3 s4 s5 s6 s7) =  xor r0 s0
                                       .|. xor r1 s1
                                       .|. xor r2 s2
                                       .|. xor r3 s3
                                       .|. xor r4 s4
                                       .|. xor r5 s5
                                       .|. xor r6 s6
                                       .|. xor r7 s7
                                       == 0

parseKey128 :: Parser KEY128
parseKey128 = KEY128 <$> parse
                     <*> parse
                     <*> parse
                     <*> parse

writeKey128 :: KEY128 -> Write
writeKey128 (KEY128 s0 s1 s2 s3) = write s0
                                <> write s1
                                <> write s2
                                <> write s3

instance Storable KEY128 where
  sizeOf    _ = 4 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseKey128
  poke cptr key128 = runWrite (castPtr cptr) $ writeKey128 key128

instance EndianStore KEY128 where
  load cptr = runParser cptr parseKey128
  store cptr key128 = runWrite cptr $ writeKey128 key128

instance CryptoSerialize KEY128

parseKey192 :: Parser KEY192
parseKey192 = KEY192 <$> parse
                     <*> parse
                     <*> parse
                     <*> parse
                     <*> parse
                     <*> parse

writeKey192 :: KEY192 -> Write
writeKey192 (KEY192 s0 s1 s2 s3 s4 s5) = write s0
                                      <> write s1
                                      <> write s2
                                      <> write s3
                                      <> write s4
                                      <> write s5

instance Storable KEY192 where
  sizeOf    _ = 6 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseKey192
  poke cptr key192 = runWrite (castPtr cptr) $ writeKey192 key192

instance EndianStore KEY192 where
  load cptr = runParser cptr parseKey192
  store cptr key192 = runWrite cptr $ writeKey192 key192

instance CryptoSerialize KEY192

parseKey256 :: Parser KEY256
parseKey256 = KEY256 <$> parse
                     <*> parse
                     <*> parse
                     <*> parse
                     <*> parse
                     <*> parse
                     <*> parse
                     <*> parse

writeKey256 :: KEY256 -> Write
writeKey256 (KEY256 s0 s1 s2 s3 s4 s5 s6 s7) = write s0
                                            <> write s1
                                            <> write s2
                                            <> write s3
                                            <> write s4
                                            <> write s5
                                            <> write s6
                                            <> write s7

instance Storable KEY256 where
  sizeOf    _ = 8 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseKey256
  poke cptr key256 = runWrite (castPtr cptr) $ writeKey256 key256

instance EndianStore KEY256 where
  load cptr = runParser cptr parseKey256
  store cptr key256 = runWrite cptr $ writeKey256 key256

instance CryptoSerialize KEY256

showWord32 :: Word32BE -> ShowS
showWord32 w = showString $ "0x" ++ replicate (8 - length hex) '0' ++ hex
  where
    hex = showHex w ""
