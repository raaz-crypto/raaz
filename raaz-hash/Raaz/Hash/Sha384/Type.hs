{-|

This module exposes the `SHA384` hash constructor. You would hardly
need to import the module directly as you would want to treat the
`SHA384` type as an opaque type for type safety. This module is
exported only for special uses like writing a test case or defining a
binary instance etc.

-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash.Sha384.Type
       ( SHA384(..)
       , IV(SHA384IV)
       ) where

import Control.Applicative ((<$>), (<*>))
import Data.Bits(xor, (.|.))
import Data.Default
import Data.Typeable(Typeable)
import Foreign.Storable(Storable(..))

import Raaz.Primitives
import Raaz.Types
import Raaz.Util.Ptr(loadFromIndex, storeAtIndex)

import Raaz.Hash.Sha.Util
import Raaz.Hash.Sha512.Type(SHA512(..))


----------------------------- SHA384 -------------------------------------------

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

instance Primitive SHA384 where
  blockSize _ = cryptoCoerce $ BITS (1024 :: Int)
  {-# INLINE blockSize #-}
  newtype IV SHA384 = SHA384IV SHA512

instance SafePrimitive SHA384

instance HasPadding SHA384 where
  maxAdditionalBlocks _ = 1
  padLength = padLength128
  padding   = padding128

instance Default (IV SHA384) where
  def = SHA384IV $ SHA512 0xcbbb9d5dc1059ed8
                          0x629a292a367cd507
                          0x9159015a3070dd17
                          0x152fecd8f70e5939
                          0x67332667ffc00b31
                          0x8eb44a8768581511
                          0xdb0c2e0d64f98fa7
                          0x47b5481dbefa4fa4
