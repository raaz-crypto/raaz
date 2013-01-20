{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}

module Raaz.Hash.Sha
       ( SHA1(..)
       , SHA256(..)
       , SHA224(..)
       ) where

import Control.Applicative ((<$>), (<*>))
import Data.Bits(xor, (.|.))
import Data.Typeable(Typeable)
import Foreign.Storable(Storable(..))
import Test.QuickCheck(Arbitrary(..))

import Raaz.Primitives
import Raaz.Util.Ptr(loadFromIndex, storeAtIndex)
import Raaz.Types

-- | The SHA1 hash value.
data SHA1 = SHA1 {-# UNPACK #-} !Word32BE
                 {-# UNPACK #-} !Word32BE
                 {-# UNPACK #-} !Word32BE
                 {-# UNPACK #-} !Word32BE
                 {-# UNPACK #-} !Word32BE deriving (Show, Typeable)

-- | Timing independent equality testing.
instance Eq SHA1 where
  (==) (SHA1 g0 g1 g2 g3 g4) (SHA1 h0 h1 h2 h3 h4) =   xor g0 h0
                                                   .|. xor g1 h1
                                                   .|. xor g2 h2
                                                   .|. xor g3 h3
                                                   .|. xor g4 h4
                                                   == 0


instance Storable SHA1 where
  sizeOf    _ = 5 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: Word32BE)
  peekByteOff ptr pos = SHA1 <$> peekByteOff ptr pos0
                             <*> peekByteOff ptr pos1
                             <*> peekByteOff ptr pos2
                             <*> peekByteOff ptr pos3
                             <*> peekByteOff ptr pos4
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          offset = sizeOf (undefined:: Word32BE)

  pokeByteOff ptr pos (SHA1 h0 h1 h2 h3 h4) =  pokeByteOff ptr pos0 h0
                                            >> pokeByteOff ptr pos1 h1
                                            >> pokeByteOff ptr pos2 h2
                                            >> pokeByteOff ptr pos3 h3
                                            >> pokeByteOff ptr pos4 h4
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          offset = sizeOf (undefined:: Word32BE)

instance CryptoStore SHA1 where
  load cptr = SHA1 <$> load cptr
                   <*> loadFromIndex cptr 1
                   <*> loadFromIndex cptr 2
                   <*> loadFromIndex cptr 3
                   <*> loadFromIndex cptr 4

  store cptr (SHA1 h0 h1 h2 h3 h4) =  store cptr h0
                                   >> storeAtIndex cptr 1 h1
                                   >> storeAtIndex cptr 2 h2
                                   >> storeAtIndex cptr 3 h3
                                   >> storeAtIndex cptr 4 h4

instance Arbitrary SHA1 where
  arbitrary = SHA1 <$> arbitrary   -- h0
                   <*> arbitrary   -- h1
                   <*> arbitrary   -- h2
                   <*> arbitrary   -- h3
                   <*> arbitrary   -- h4

instance BlockPrimitive SHA1 where
  blockSize _ = cryptoCoerce $ BITS (512 :: Int)
  {-# INLINE blockSize #-}

-- | The Sha256 hash value. Used in implementation of Sha224 as well.
data SHA256 = SHA256 {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE deriving (Show, Typeable)

-- | Timing independent equality testing for sha256
instance Eq SHA256 where
  (==) (SHA256 g0 g1 g2 g3 g4 g5 g6 g7) (SHA256 h0 h1 h2 h3 h4 h5 h6 h7)
      =   xor g0 h0
      .|. xor g1 h1
      .|. xor g2 h2
      .|. xor g3 h3
      .|. xor g4 h4
      .|. xor g5 h5
      .|. xor g6 h6
      .|. xor g7 h7
      == 0


instance Storable SHA256 where
  sizeOf    _ = 8 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: Word32BE)
  peekByteOff ptr pos = SHA256 <$> peekByteOff ptr pos0
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
          offset = sizeOf (undefined:: Word32BE)

  pokeByteOff ptr pos (SHA256 h0 h1 h2 h3 h4 h5 h6 h7)
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
          offset = sizeOf (undefined:: Word32BE)

instance CryptoStore SHA256 where
  load cptr = SHA256 <$> load cptr
                     <*> loadFromIndex cptr 1
                     <*> loadFromIndex cptr 2
                     <*> loadFromIndex cptr 3
                     <*> loadFromIndex cptr 4
                     <*> loadFromIndex cptr 5
                     <*> loadFromIndex cptr 6
                     <*> loadFromIndex cptr 7

  store cptr (SHA256 h0 h1 h2 h3 h4 h5 h6 h7) =  store cptr h0
                                              >> storeAtIndex cptr 1 h1
                                              >> storeAtIndex cptr 2 h2
                                              >> storeAtIndex cptr 3 h3
                                              >> storeAtIndex cptr 4 h4
                                              >> storeAtIndex cptr 5 h5
                                              >> storeAtIndex cptr 6 h6
                                              >> storeAtIndex cptr 7 h7

instance Arbitrary SHA256 where
  arbitrary = SHA256 <$> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary

instance BlockPrimitive SHA256 where
  blockSize _ = cryptoCoerce $ BITS (512 :: Int)
  {-# INLINE blockSize #-}

-- | Sha224 hash value which consist of 7 32bit words.
data SHA224 = SHA224 {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE
                     {-# UNPACK #-} !Word32BE deriving (Show, Typeable)

-- | Timing independent equality testing for sha224
instance Eq SHA224 where
  (==) (SHA224 g0 g1 g2 g3 g4 g5 g6) (SHA224 h0 h1 h2 h3 h4 h5 h6)
      =   xor g0 h0
      .|. xor g1 h1
      .|. xor g2 h2
      .|. xor g3 h3
      .|. xor g4 h4
      .|. xor g5 h5
      .|. xor g6 h6
      == 0


instance Storable SHA224 where
  sizeOf    _ = 7 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: Word32BE)
  peekByteOff ptr pos = SHA224 <$> peekByteOff ptr pos0
                               <*> peekByteOff ptr pos1
                               <*> peekByteOff ptr pos2
                               <*> peekByteOff ptr pos3
                               <*> peekByteOff ptr pos4
                               <*> peekByteOff ptr pos5
                               <*> peekByteOff ptr pos6
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          pos6   = pos5 + offset
          offset = sizeOf (undefined:: Word32BE)

  pokeByteOff ptr pos (SHA224 h0 h1 h2 h3 h4 h5 h6)
      =  pokeByteOff ptr pos0 h0
      >> pokeByteOff ptr pos1 h1
      >> pokeByteOff ptr pos2 h2
      >> pokeByteOff ptr pos3 h3
      >> pokeByteOff ptr pos4 h4
      >> pokeByteOff ptr pos5 h5
      >> pokeByteOff ptr pos6 h6
    where pos0   = pos
          pos1   = pos0 + offset
          pos2   = pos1 + offset
          pos3   = pos2 + offset
          pos4   = pos3 + offset
          pos5   = pos4 + offset
          pos6   = pos5 + offset
          offset = sizeOf (undefined:: Word32BE)

instance CryptoStore SHA224 where
  load cptr = SHA224 <$> load cptr
                     <*> loadFromIndex cptr 1
                     <*> loadFromIndex cptr 2
                     <*> loadFromIndex cptr 3
                     <*> loadFromIndex cptr 4
                     <*> loadFromIndex cptr 5
                     <*> loadFromIndex cptr 6

  store cptr (SHA224 h0 h1 h2 h3 h4 h5 h6) =  store cptr h0
                                           >> storeAtIndex cptr 1 h1
                                           >> storeAtIndex cptr 2 h2
                                           >> storeAtIndex cptr 3 h3
                                           >> storeAtIndex cptr 4 h4
                                           >> storeAtIndex cptr 5 h5
                                           >> storeAtIndex cptr 6 h6

instance Arbitrary SHA224 where
  arbitrary = SHA224 <$> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary
                     <*> arbitrary

instance BlockPrimitive SHA224 where
  blockSize _ = cryptoCoerce $ BITS (512 :: Int)
  {-# INLINE blockSize #-}
