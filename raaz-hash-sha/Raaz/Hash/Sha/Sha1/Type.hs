{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}

module Raaz.Hash.Sha.Sha1.Type
       ( SHA1(..)
       ) where

import Control.Applicative ((<$>), (<*>))
import Data.Bits(xor, (.|.))
import Data.Typeable(Typeable)
import Foreign.Storable(Storable(..))

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
