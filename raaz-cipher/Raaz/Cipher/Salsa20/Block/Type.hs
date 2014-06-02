{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Cipher.Salsa20.Block.Type
       ( STATE(..)
       , Matrix(..)
       , SplitWord64(..)
       , KEY128(..), KEY256(..)
       , Nonce(..), Counter(..)
       , xorState, orState, addState
       , transposeMatrix, addMatrix, xorMatrix
       ) where

import Control.Applicative
import Data.Bits
import Data.Monoid
import Data.Typeable
import Foreign.Storable
import Foreign.Ptr         (castPtr)
import Numeric             (showHex)

import Raaz.Types
import Raaz.Parse.Unsafe
import Raaz.Write.Unsafe

import Raaz.Serialize

-- | State which consists of 4 `Word32LE`.
data STATE = STATE {-# UNPACK #-} !Word32LE
                   {-# UNPACK #-} !Word32LE
                   {-# UNPACK #-} !Word32LE
                   {-# UNPACK #-} !Word32LE
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

-- | Timing independent equality testing for STATE
instance Eq STATE where
  (==) (STATE r0 r1 r2 r3)
       (STATE s0 s1 s2 s3) =  xor r0 s0
                          .|. xor r1 s1
                          .|. xor r2 s2
                          .|. xor r3 s3
                          == 0

-- | xor for `STATE`.
xorState :: STATE -> STATE -> STATE
xorState (STATE w0 w1 w2 w3) (STATE x0 x1 x2 x3) = STATE (w0 `xor` x0)
                                                         (w1 `xor` x1)
                                                         (w2 `xor` x2)
                                                         (w3 `xor` x3)
{-# INLINE xorState #-}

-- | or for `STATE`
orState :: STATE -> STATE -> STATE
orState (STATE w0 w1 w2 w3) (STATE x0 x1 x2 x3) = STATE (w0 .|. x0)
                                                        (w1 .|. x1)
                                                        (w2 .|. x2)
                                                        (w3 .|. x3)
{-# INLINE orState #-}

-- | Summation for `STATE`
addState :: STATE -> STATE -> STATE
addState (STATE w0 w1 w2 w3) (STATE x0 x1 x2 x3) = STATE (w0 + x0)
                                                         (w1 + x1)
                                                         (w2 + x2)
                                                         (w3 + x3)
{-# INLINE addState #-}

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
  sizeOf    _ = 4 * sizeOf (undefined :: Word32LE)
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseState
  poke cptr state = runWrite (castPtr cptr) $ writeState state

instance EndianStore STATE where
  load cptr = runParser cptr parseState
  store cptr state = runWrite cptr $ writeState state

instance CryptoSerialize STATE

-- | Matrix which consists of 4 `STATE`.
data Matrix = Matrix {-# UNPACK #-} !STATE
                     {-# UNPACK #-} !STATE
                     {-# UNPACK #-} !STATE
                     {-# UNPACK #-} !STATE
         deriving Typeable

instance Show Matrix where
  show (Matrix w0 w1 w2 w3) = showString "Matrix "
                           . showsPrec 1 w0
                           . showChar ' '
                           . showsPrec 1 w1
                           . showChar ' '
                           . showsPrec 1 w2
                           . showChar ' '
                           $ showsPrec 1 w3 ""

-- | Timing independent equality testing for Matrix
instance Eq Matrix where
  (==) (Matrix r0 r1 r2 r3)
       (Matrix s0 s1 s2 s3) =  xorState r0 s0
                           `orState` xorState r1 s1
                           `orState` xorState r2 s2
                           `orState` xorState r3 s3
                           == STATE 0 0 0 0

parseMatrix :: Parser Matrix
parseMatrix = Matrix <$> parse
                    <*> parse
                    <*> parse
                    <*> parse

writeMatrix :: Matrix -> Write
writeMatrix (Matrix s0 s1 s2 s3) = write s0
                               <> write s1
                               <> write s2
                               <> write s3


instance Storable Matrix where
  sizeOf    _ = 4 * sizeOf (undefined :: STATE)
  alignment _ = alignment  (undefined :: STATE)
  peek cptr = runParser (castPtr cptr) parseMatrix
  poke cptr matrix = runWrite (castPtr cptr) $ writeMatrix matrix

instance EndianStore Matrix where
  load cptr = runParser cptr parseMatrix
  store cptr matrix = runWrite cptr $ writeMatrix matrix

instance CryptoSerialize Matrix

-- | Transpose of the `Matrix`.
transposeMatrix :: Matrix -> Matrix
transposeMatrix (Matrix (STATE s0  s1  s2  s3)
                        (STATE s4  s5  s6  s7)
                        (STATE s8  s9  s10 s11)
                        (STATE s12 s13 s14 s15)) =
                 Matrix (STATE s0  s4  s8  s12)
                        (STATE s1  s5  s9  s13)
                        (STATE s2  s6  s10 s14)
                        (STATE s3  s7  s11 s15)
{-# INLINE transposeMatrix #-}

addMatrix :: Matrix -> Matrix -> Matrix
addMatrix (Matrix w0 w1 w2 w3) (Matrix x0 x1 x2 x3) = Matrix (w0 `addState` x0)
                                                             (w1 `addState` x1)
                                                             (w2 `addState` x2)
                                                             (w3 `addState` x3)
{-# INLINE addMatrix #-}

xorMatrix :: Matrix -> Matrix -> Matrix
xorMatrix (Matrix w0 w1 w2 w3) (Matrix x0 x1 x2 x3) = Matrix (w0 `xorState` x0)
                                                             (w1 `xorState` x1)
                                                             (w2 `xorState` x2)
                                                             (w3 `xorState` x3)
{-# INLINE xorMatrix #-}

-- | 128 Bit Key
data KEY128 = KEY128 {-# UNPACK #-} !Word32LE
                     {-# UNPACK #-} !Word32LE
                     {-# UNPACK #-} !Word32LE
                     {-# UNPACK #-} !Word32LE
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


-- | 256 Bit Key
data KEY256 = KEY256 {-# UNPACK #-} !Word32LE
                     {-# UNPACK #-} !Word32LE
                     {-# UNPACK #-} !Word32LE
                     {-# UNPACK #-} !Word32LE
                     {-# UNPACK #-} !Word32LE
                     {-# UNPACK #-} !Word32LE
                     {-# UNPACK #-} !Word32LE
                     {-# UNPACK #-} !Word32LE
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
  sizeOf    _ = 4 * sizeOf (undefined :: Word32LE)
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseKey128
  poke cptr key128 = runWrite (castPtr cptr) $ writeKey128 key128

instance EndianStore KEY128 where
  load cptr = runParser cptr parseKey128
  store cptr key128 = runWrite cptr $ writeKey128 key128

instance CryptoSerialize KEY128

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
  sizeOf    _ = 8 * sizeOf (undefined :: Word32LE)
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseKey256
  poke cptr key256 = runWrite (castPtr cptr) $ writeKey256 key256

instance EndianStore KEY256 where
  load cptr = runParser cptr parseKey256
  store cptr key256 = runWrite cptr $ writeKey256 key256

instance CryptoSerialize KEY256

-- | Performs summation for `Matrix`.
showWord32 :: Word32LE -> ShowS
showWord32 w = showString $ "0x" ++ replicate (8 - length hex) '0' ++ hex
  where
    hex = showHex w ""


data SplitWord64 = SplitWord64 {-# UNPACK #-} !Word32LE
                               {-# UNPACK #-} !Word32LE
                   deriving Typeable

-- | Hexadecimal Show instance
instance Show SplitWord64 where
  show (SplitWord64 w0 w1) =  showString "SplitWord64 "
                            . showWord32 w0
                            . showChar ' '
                            $ showWord32 w1 ""

instance Eq SplitWord64 where
  (==) (SplitWord64 r0 r1)
       (SplitWord64 s0 s1) =   xor r0 s0
                           .|. xor r1 s1
                           == 0

parseSplitWord64 :: Parser SplitWord64
parseSplitWord64 = SplitWord64 <$> parse
                               <*> parse

writeSplitWord64 :: SplitWord64 -> Write
writeSplitWord64 (SplitWord64 s0 s1) = write s0
                                    <> write s1

instance Storable SplitWord64 where
  sizeOf    _ = 2 * sizeOf (undefined :: Word32LE)
  alignment _ = alignment  (undefined :: CryptoAlign)
  peek cptr = runParser (castPtr cptr) parseSplitWord64
  poke cptr splitWord64 = runWrite (castPtr cptr) $ writeSplitWord64 splitWord64

instance EndianStore SplitWord64 where
  load cptr = runParser cptr parseSplitWord64
  store cptr splitWord64 = runWrite cptr $ writeSplitWord64 splitWord64

instance CryptoSerialize SplitWord64

-- | Nonce of 8 Byte.
newtype Nonce   = Nonce SplitWord64
  deriving (Eq, Show, Typeable, EndianStore, Storable)

instance CryptoSerialize Nonce

-- | Counter of 8 Byte.
newtype Counter = Counter SplitWord64
  deriving (Eq, Show, Typeable, EndianStore, Storable)

instance CryptoSerialize Counter
