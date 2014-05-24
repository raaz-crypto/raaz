{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash.Blake256.Type
       ( BLAKE256(..)
       , Salt(..)
       , Cxt(BLAKE256Cxt)
       ) where

import Control.Applicative ((<$>), (<*>))
import Data.Bits(xor, (.|.))
import Data.Default
import Data.Word
import Data.Monoid
import Data.Typeable(Typeable)
import Foreign.Ptr(castPtr)
import Foreign.Storable(Storable(..))

import Raaz.Parse.Unsafe
import Raaz.Primitives
import Raaz.Types
import Raaz.Util.Ptr(loadFromIndex, storeAtIndex)
import Raaz.Write.Unsafe

import Raaz.Hash.Sha.Util

------------------------------------BLAKE256----------------------------------

-- | The Blake256 hash value.
data BLAKE256 = BLAKE256 {-# UNPACK #-} !Word32BE
						             {-# UNPACK #-} !Word32BE
						             {-# UNPACK #-} !Word32BE
						             {-# UNPACK #-} !Word32BE
						             {-# UNPACK #-} !Word32BE
						             {-# UNPACK #-} !Word32BE
						             {-# UNPACK #-} !Word32BE
						             {-# UNPACK #-} !Word32BE deriving (Show, Typeable)

-- | The Blake256 salt value.
data Salt = Salt {-# UNPACK #-} !Word32BE
				         {-# UNPACK #-} !Word32BE
				         {-# UNPACK #-} !Word32BE
				         {-# UNPACK #-} !Word32BE deriving (Show, Typeable)

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

instance Digestible BLAKE256 where
  type Digest BLAKE256 = BLAKE256
  toDigest (BLAKE256Cxt b s c) = b      

instance Storable BLAKE256 where
  sizeOf    _ = 8 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: Word32BE)
  
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

instance Storable (Cxt BLAKE256) where
  sizeOf    _ = 14 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: Word32BE)
  
  peek ptr = runParser cptr parseBLAKE256Cxt
    where parseBLAKE256Cxt = BLAKE256Cxt <$> parseStorable
                                         <*> parseStorable
                                         <*> parseStorable
          cptr = castPtr ptr

  poke ptr (BLAKE256Cxt b@(BLAKE256 h0 h1 h2 h3 h4 h5 h6 h7) 
                        s@(Salt s0 s1 s2 s3)
                        t 
           ) = runWrite cptr writeBLAKE256Cxt
    where writeBLAKE256Cxt =  writeStorable h0
                           <> writeStorable h1
                           <> writeStorable h2
                           <> writeStorable h3
                           <> writeStorable h4
                           <> writeStorable h5
                           <> writeStorable h6
                           <> writeStorable h7
                           <> writeStorable s0
                           <> writeStorable s1
                           <> writeStorable h2
                           <> writeStorable h3
                           <> writeStorable t
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
  sizeOf    _ = 4 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: Word32BE)
  
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
  blockSize _ = cryptoCoerce $ BITS (512 :: Int)
  {-# INLINE blockSize #-}
  data Cxt BLAKE256 = BLAKE256Cxt BLAKE256 Salt (BITS Word64)

instance SafePrimitive BLAKE256

instance HasPadding BLAKE256 where
  maxAdditionalBlocks _ = 1
  padLength = blakePadLength 8
  padding   = blakePadding   8

instance Default (Cxt BLAKE256) where
  def = let
          blake = BLAKE256 0x6a09e667
                           0xbb67ae85
                           0x3c6ef372
                           0xa54ff53a
                           0x510e527f
                           0x9b05688c
                           0x1f83d9ab
                           0x5be0cd19
          salt = Salt 0 0 0 0
        in
            BLAKE256Cxt blake salt 0 

instance Default Salt where
  def = Salt 0 0 0 0
