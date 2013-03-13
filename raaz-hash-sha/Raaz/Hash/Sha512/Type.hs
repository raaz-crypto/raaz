{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}

module Raaz.Hash.Sha512.Type
       ( SHA512(..)
       , SHA384(..)
       ) where

import Control.Applicative ((<$>), (<*>))
import Data.Bits(xor, (.|.))
import Data.Typeable(Typeable)
import Foreign.Storable(Storable(..))

import Raaz.Util.Ptr(loadFromIndex, storeAtIndex)
import Raaz.Types

-- | The Sha512 hash value. Used in implementation of Sha384 as well.
data SHA512 = SHA512 {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE deriving (Show, Typeable)

-- | Timing independent equality testing for sha512
instance Eq SHA512 where
  (==) (SHA512 g0 g1 g2 g3 g4 g5 g6 g7) (SHA512 h0 h1 h2 h3 h4 h5 h6 h7)
      =   xor g0 h0
      .|. xor g1 h1
      .|. xor g2 h2
      .|. xor g3 h3
      .|. xor g4 h4
      .|. xor g5 h5
      .|. xor g6 h6
      .|. xor g7 h7
      == 0


instance Storable SHA512 where
  sizeOf    _ = 8 * sizeOf (undefined :: Word64BE)
  alignment _ = alignment  (undefined :: Word64BE)
  peekByteOff ptr pos = SHA512 <$> peekByteOff ptr pos0
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
          offset = sizeOf (undefined:: Word64BE)

  pokeByteOff ptr pos (SHA512 h0 h1 h2 h3 h4 h5 h6 h7)
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
          offset = sizeOf (undefined:: Word64BE)

instance CryptoStore SHA512 where
  load cptr = SHA512 <$> load cptr
                     <*> loadFromIndex cptr 1
                     <*> loadFromIndex cptr 2
                     <*> loadFromIndex cptr 3
                     <*> loadFromIndex cptr 4
                     <*> loadFromIndex cptr 5
                     <*> loadFromIndex cptr 6
                     <*> loadFromIndex cptr 7

  store cptr (SHA512 h0 h1 h2 h3 h4 h5 h6 h7) =  store cptr h0
                                              >> storeAtIndex cptr 1 h1
                                              >> storeAtIndex cptr 2 h2
                                              >> storeAtIndex cptr 3 h3
                                              >> storeAtIndex cptr 4 h4
                                              >> storeAtIndex cptr 5 h5
                                              >> storeAtIndex cptr 6 h6
                                              >> storeAtIndex cptr 7 h7


-- | The Sha384 hash value.
data SHA384 = SHA384 {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE
                     {-# UNPACK #-} !Word64BE deriving (Show, Typeable)

-- | Timing independent equality testing for sha384
instance Eq SHA384 where
  (==) (SHA384 g0 g1 g2 g3 g4 g5) (SHA384 h0 h1 h2 h3 h4 h5)
      =   xor g0 h0
      .|. xor g1 h1
      .|. xor g2 h2
      .|. xor g3 h3
      .|. xor g4 h4
      .|. xor g5 h5
      == 0


instance Storable SHA384 where
  sizeOf    _ = 6 * sizeOf (undefined :: Word64BE)
  alignment _ = alignment  (undefined :: Word64BE)
  peekByteOff ptr pos = SHA384 <$> peekByteOff ptr pos0
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
          offset = sizeOf (undefined:: Word64BE)

  pokeByteOff ptr pos (SHA384 h0 h1 h2 h3 h4 h5)
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
          offset = sizeOf (undefined:: Word64BE)

instance CryptoStore SHA384 where
  load cptr = SHA384 <$> load cptr
                     <*> loadFromIndex cptr 1
                     <*> loadFromIndex cptr 2
                     <*> loadFromIndex cptr 3
                     <*> loadFromIndex cptr 4
                     <*> loadFromIndex cptr 5

  store cptr (SHA384 h0 h1 h2 h3 h4 h5) =  store cptr h0
                                        >> storeAtIndex cptr 1 h1
                                        >> storeAtIndex cptr 2 h2
                                        >> storeAtIndex cptr 3 h3
                                        >> storeAtIndex cptr 4 h4
                                        >> storeAtIndex cptr 5 h5
