{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DataKinds                  #-}

module Raaz.Cipher.AES.Block.Type
       ( STATE(..)
       , KEY128(..)
       , KEY192(..)
       , KEY256(..)
       , Expanded(..)
       , AEScxt(..)
       ) where

import Control.Applicative       ( (<$>), (<*>)         )
import Data.Bits                 ( xor, (.|.), Bits(..) )
import Data.Monoid               ( (<>)                 )
import Data.String
import Data.Typeable             ( Typeable             )
import Data.Word
import Foreign.Ptr               ( castPtr              )
import Foreign.Storable          ( sizeOf,Storable(..)  )


import Raaz.Core.Encode
import Raaz.Core.Types
import Raaz.Core.Parse.Unsafe
import Raaz.Core.Write.Unsafe



-- | AES Cxt (Used in CBC and CTR mode)
newtype AEScxt = AEScxt STATE
         deriving (Show,Typeable,Eq,Storable)

--------------------------- The internal state of AES ------------------------

-- | AES State
data STATE = STATE {-# UNPACK #-} !(BE Word32)
                   {-# UNPACK #-} !(BE Word32)
                   {-# UNPACK #-} !(BE Word32)
                   {-# UNPACK #-} !(BE Word32)
         deriving Typeable

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

parseStateStorable :: Parser STATE
parseStateStorable = STATE <$> parseStorable
                           <*> parseStorable
                           <*> parseStorable
                           <*> parseStorable

writeStateStorable :: STATE -> Write
writeStateStorable (STATE s0 s1 s2 s3) =  writeStorable s0
                                       <> writeStorable s1
                                       <> writeStorable s2
                                       <> writeStorable s3


instance Storable STATE where
  sizeOf    _ = 4 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseStateStorable
  poke cptr state = runWrite (castPtr cptr) $ writeStateStorable state

instance EndianStore STATE where
  load cptr = runParser cptr parseState
  store cptr state = runWrite cptr $ writeState state

instance Encodable STATE


instance IsString STATE where
  fromString = fromBase16

instance Show STATE where
  show = showBase16

------------------------------------------- AES keys -------------------------------------


-- | 128 Bit Key
data KEY128 = KEY128 {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
         deriving Typeable

-- | Timing independent equality testing for KEY128
instance Eq KEY128 where
  (==) (KEY128 r0 r1 r2 r3)
       (KEY128 s0 s1 s2 s3) =  xor r0 s0
                           .|. xor r1 s1
                           .|. xor r2 s2
                           .|. xor r3 s3
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

parseStorableKey128 :: Parser KEY128
parseStorableKey128 = KEY128 <$> parseStorable
                             <*> parseStorable
                             <*> parseStorable
                             <*> parseStorable

writeStorableKey128 :: KEY128 -> Write
writeStorableKey128 (KEY128 s0 s1 s2 s3) = writeStorable s0
                                         <> writeStorable s1
                                         <> writeStorable s2
                                         <> writeStorable s3


instance Storable KEY128 where
  sizeOf    _ = 4 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseStorableKey128
  poke cptr key128 = runWrite (castPtr cptr) $ writeStorableKey128 key128

instance EndianStore KEY128 where
  load cptr = runParser cptr parseKey128
  store cptr key128 = runWrite cptr $ writeKey128 key128

instance Encodable KEY128

instance IsString KEY128 where
  fromString = fromBase16

instance Show KEY128 where
  show = showBase16


------------------------------------------ AES keys of 192 bit -----------------------------

-- | 192 Bit Key
data KEY192 = KEY192 {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
         deriving Typeable



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

parseStorableKey192 :: Parser KEY192
parseStorableKey192 = KEY192 <$> parseStorable
                             <*> parseStorable
                             <*> parseStorable
                             <*> parseStorable
                             <*> parseStorable
                             <*> parseStorable

writeStorableKey192 :: KEY192 -> Write
writeStorableKey192 (KEY192 s0 s1 s2 s3 s4 s5) = writeStorable s0
                                               <> writeStorable s1
                                               <> writeStorable s2
                                               <> writeStorable s3
                                               <> writeStorable s4
                                               <> writeStorable s5

instance Storable KEY192 where
  sizeOf    _ = 6 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseStorableKey192
  poke cptr key192 = runWrite (castPtr cptr) $ writeStorableKey192 key192

instance EndianStore KEY192 where
  load cptr = runParser cptr parseKey192
  store cptr key192 = runWrite cptr $ writeKey192 key192


instance Encodable KEY192

instance IsString KEY192 where
  fromString = fromBase16

instance Show KEY192 where
  show = showBase16


-- | 256 Bit Key
data KEY256 = KEY256 {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
         deriving Typeable


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

parseStorableKey256 :: Parser KEY256
parseStorableKey256 = KEY256 <$> parseStorable
                             <*> parseStorable
                             <*> parseStorable
                             <*> parseStorable
                             <*> parseStorable
                             <*> parseStorable
                             <*> parseStorable
                             <*> parseStorable

writeStorableKey256 :: KEY256 -> Write
writeStorableKey256 (KEY256 s0 s1 s2 s3 s4 s5 s6 s7) = writeStorable s0
                                                     <> writeStorable s1
                                                     <> writeStorable s2
                                                     <> writeStorable s3
                                                     <> writeStorable s4
                                                     <> writeStorable s5
                                                     <> writeStorable s6
                                                     <> writeStorable s7

instance Storable KEY256 where
  sizeOf    _ = 8 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseStorableKey256
  poke cptr key256 = runWrite (castPtr cptr) $ writeStorableKey256 key256

instance EndianStore KEY256 where
  load cptr = runParser cptr parseKey256
  store cptr key256 = runWrite cptr $ writeKey256 key256

instance Encodable KEY256

instance IsString KEY256 where
  fromString = fromBase16

instance Show KEY256 where
  show = showBase16


{-# ANN module "HLint: ignore Reduce duplication" #-}

----------------------------- Expanded keys -------------------------------


data family Expanded key :: *

-- | Expanded Key for 128 Bit Key
data instance Expanded KEY128 =
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
           deriving Show

-- | Expanded Key for 192 Bit Key
data instance Expanded KEY192 =
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
        deriving Show

-- | Expanded Key for 256 Bit Key
data instance Expanded KEY256 =
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
        deriving Show


instance Storable (Expanded KEY128)  where
  sizeOf    _ = 11 * sizeOf (undefined :: STATE)
  alignment _ = alignment  (undefined :: STATE)
  peekByteOff ptr pos = Expanded128  <$> peekByteOff ptr pos0
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

  pokeByteOff ptr pos (Expanded128  h0 h1 h2 h3 h4 h5 h6 h7 h8 h9 h10)
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

instance Storable (Expanded KEY192)  where
  sizeOf    _ = 13 * sizeOf (undefined :: STATE)
  alignment _ = alignment  (undefined :: STATE)
  peekByteOff ptr pos = Expanded192  <$> peekByteOff ptr pos0
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

  pokeByteOff ptr pos (Expanded192  h0 h1 h2 h3 h4 h5 h6 h7 h8 h9 h10
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

instance Storable (Expanded KEY256)  where
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
