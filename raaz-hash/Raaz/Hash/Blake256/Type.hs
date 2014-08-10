{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Raaz.Hash.Blake256.Type
       ( BLAKE256(..)
       , Salt(..)
       , BLAKEMem(..)
       ) where

import Control.Applicative ((<$>), (<*>))
import Data.Bits(xor, (.|.))
import Data.Word
import Data.Monoid
import Data.Typeable(Typeable)
import Foreign.Ptr(castPtr)
import Foreign.Storable(Storable(..))

import Raaz.Core.Memory
import Raaz.Core.Parse.Unsafe
import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Core.Write.Unsafe

import Raaz.Hash.Blake.Util

------------------------------------BLAKE256----------------------------------

-- | The Blake256 hash value.
data BLAKE256 = BLAKE256 {-# UNPACK #-} !(BE Word32)
                         {-# UNPACK #-} !(BE Word32)
                         {-# UNPACK #-} !(BE Word32)
                         {-# UNPACK #-} !(BE Word32)
                         {-# UNPACK #-} !(BE Word32)
                         {-# UNPACK #-} !(BE Word32)
                         {-# UNPACK #-} !(BE Word32)
                         {-# UNPACK #-} !(BE Word32) deriving (Show, Typeable)

-- | The Blake256 salt value.
data Salt = Salt {-# UNPACK #-} !(BE Word32)
                 {-# UNPACK #-} !(BE Word32)
                 {-# UNPACK #-} !(BE Word32)
                 {-# UNPACK #-} !(BE Word32) deriving (Show, Typeable)

-- | Timing independent equality testing for Blake256
instance Eq BLAKE256 where
  (==) (BLAKE256 g0 g1 g2 g3 g4 g5 g6 g7) (BLAKE256 h0 h1 h2 h3 h4 h5 h6 h7)
      =   xor g0 h0
      .|. xor g1 h1
      .|. xor g2 h2
      .|. xor g3 h3
      .|. xor g4 h4
      .|. xor g5 h5
      .|. xor g6 h6
      .|. xor g7 h7
      == 0

instance Eq Salt where
  (==) (Salt g0 g1 g2 g3) (Salt h0 h1 h2 h3)
      =  xor g0 h0
      .|. xor g1 h1
      .|. xor g2 h2
      .|. xor g3 h3
      == 0

instance HasName BLAKE256

instance Storable BLAKE256 where
  sizeOf    _ = 8 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))

  peek ptr = runParser cptr parseBLAKE256
    where parseBLAKE256 = BLAKE256 <$> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
          cptr = castPtr ptr

  poke ptr (BLAKE256 h0 h1 h2 h3 h4 h5 h6 h7) = runWrite cptr writeBLAKE256
    where writeBLAKE256 =  writeStorable h0
                        <> writeStorable h1
                        <> writeStorable h2
                        <> writeStorable h3
                        <> writeStorable h4
                        <> writeStorable h5
                        <> writeStorable h6
                        <> writeStorable h7
          cptr = castPtr ptr

instance EndianStore BLAKE256 where
  load cptr = runParser cptr parseBLAKE256
    where parseBLAKE256 = BLAKE256 <$> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse

  store cptr (BLAKE256 h0 h1 h2 h3 h4 h5 h6 h7) = runWrite cptr writeBLAKE256
    where writeBLAKE256 =  write h0
                        <> write h1
                        <> write h2
                        <> write h3
                        <> write h4
                        <> write h5
                        <> write h6
                        <> write h7

instance Storable Salt where
  sizeOf    _ = 4 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))

  peek ptr = runParser cptr parseSalt
    where parseSalt = Salt <$> parseStorable
               <*> parseStorable
               <*> parseStorable
               <*> parseStorable
          cptr = castPtr ptr

  poke ptr (Salt s0 s1 s2 s3) = runWrite cptr writeSalt
    where writeSalt = writeStorable s0
           <> writeStorable s1
           <> writeStorable s2
           <> writeStorable s3
          cptr = castPtr ptr

instance EndianStore Salt where
  load cptr = runParser cptr parseSalt
    where parseSalt = Salt <$> parse
                           <*> parse
                           <*> parse
                           <*> parse

  store cptr (Salt s0 s1 s2 s3) = runWrite cptr writeSalt
    where writeSalt = write s0
                   <> write s1
                   <> write s2
                   <> write s3

instance Primitive BLAKE256 where
  blockSize _ = BYTES 64
  {-# INLINE blockSize #-}
  type Cxt BLAKE256 = (BLAKE256, Salt)

instance SafePrimitive BLAKE256

instance HasPadding BLAKE256 where
  maxAdditionalBlocks _ = 1
  padLength = blakePadLength 8
  padding   = blakePadding   8

-- | Memory for BLAKE. It stores three things
--
-- 1. Blake hash value for data processed so far
-- 2. Salt used
-- 3. Counter of bits hashed so far
--
newtype BLAKEMem blake = BLAKEMem (CryptoCell blake, CryptoCell Salt, CryptoCell (BITS Word64))
                       deriving Memory

instance Storable blake => InitializableMemory (BLAKEMem blake) where

  type IV (BLAKEMem blake) = (blake, Salt)

  initializeMemory (BLAKEMem (cblake, csalt, ccounter)) (blake,salt) = do
    cellStore cblake blake
    cellStore csalt salt
    cellStore ccounter 0

instance Storable blake => FinalizableMemory (BLAKEMem blake) where

  type FV (BLAKEMem blake) = (blake, Salt)

  finalizeMemory (BLAKEMem (cblake, csalt, _)) = do
    blake <- cellLoad cblake
    salt <- cellLoad csalt
    return (blake, salt)
