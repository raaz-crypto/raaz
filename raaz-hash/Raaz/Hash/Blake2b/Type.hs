{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash.Blake2b.Type
       ( BLAKE2B(..)
       , Salt(..)       
       , Cxt(BLAKE2BCxt)
       ) where

import Control.Applicative ((<$>), (<*>))
import Data.Bits(xor, (.|.))
import Data.Default
import Data.Word
import Data.Monoid
import Data.Typeable(Typeable)
import Foreign.Ptr(castPtr)
import Foreign.Storable(Storable(..))

import Raaz.Core.Parse.Unsafe
import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Core.Write.Unsafe

import Raaz.Hash.Sha.Util

------------------------------------BLAKE2B----------------------------------

-- | The Blake2b hash value.
data BLAKE2B = BLAKE2B   {-# UNPACK #-} !Word64LE
                         {-# UNPACK #-} !Word64LE
                         {-# UNPACK #-} !Word64LE
                         {-# UNPACK #-} !Word64LE
                         {-# UNPACK #-} !Word64LE
                         {-# UNPACK #-} !Word64LE
                         {-# UNPACK #-} !Word64LE
                         {-# UNPACK #-} !Word64LE deriving (Show, Typeable)

-- | The Blake2b salt value.
data Salt = Salt {-# UNPACK #-} !Word64LE
                 {-# UNPACK #-} !Word64LE deriving (Show, Typeable)         
               

-- | The Blake2b counter value

-- | Timing independent equality testing for Blake2b
instance Eq BLAKE2B where
  (==) (BLAKE2B g0 g1 g2 g3 g4 g5 g6 g7) (BLAKE2B h0 h1 h2 h3 h4 h5 h6 h7)
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
  (==) (Salt g0 g1) (Salt h0 h1)
      =  xor g0 h0
      .|. xor g1 h1
      == 0
      

instance HasName BLAKE2B

instance Digestible BLAKE2B where
  type Digest BLAKE2B = BLAKE2B
  toDigest (BLAKE2BCxt b _ _) = b

instance Storable BLAKE2B where
  sizeOf    _ = 8 * sizeOf (undefined :: Word64LE)
  alignment _ = alignment  (undefined :: Word64LE)

  peek ptr = runParser cptr parseBLAKE2B
    where parseBLAKE2B = BLAKE2B   <$> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
          cptr = castPtr ptr

  poke ptr (BLAKE2B h0 h1 h2 h3 h4 h5 h6 h7) = runWrite cptr writeBLAKE2B
    where writeBLAKE2B  =  writeStorable h0
                        <> writeStorable h1
                        <> writeStorable h2
                        <> writeStorable h3
                        <> writeStorable h4
                        <> writeStorable h5
                        <> writeStorable h6
                        <> writeStorable h7
          cptr = castPtr ptr

instance Storable (Cxt BLAKE2B) where
  sizeOf    _ = 11 * sizeOf (undefined :: Word64LE)
  alignment _ = alignment   (undefined :: Word64LE)

  peek ptr = runParser cptr parseBLAKE2BCxt
    where parseBLAKE2BCxt = BLAKE2BCxt   <$> parseStorable    -- not clear
                                         <*> parseStorable
                                         <*> parseStorable                                         
          cptr = castPtr ptr

  poke ptr (BLAKE2BCxt (BLAKE2B h0 h1 h2 h3 h4 h5 h6 h7)
                       (Salt s0 s1)
                       t
           ) = runWrite cptr writeBLAKE2BCxt
    where writeBLAKE2BCxt =   writeStorable h0
                           <> writeStorable h1
                           <> writeStorable h2
                           <> writeStorable h3
                           <> writeStorable h4
                           <> writeStorable h5
                           <> writeStorable h6
                           <> writeStorable h7
                           <> writeStorable s0
                           <> writeStorable s1
                           <> writeStorable t                           
          cptr = castPtr ptr

instance EndianStore BLAKE2B where
  load cptr = runParser cptr parseBLAKE2B
    where parseBLAKE2B = BLAKE2B   <$> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse

  store cptr (BLAKE2B h0 h1 h2 h3 h4 h5 h6 h7) = runWrite cptr writeBLAKE2B
    where writeBLAKE2B =   write h0
                        <> write h1
                        <> write h2
                        <> write h3
                        <> write h4
                        <> write h5
                        <> write h6
                        <> write h7

instance Storable Salt where
  sizeOf    _ = 2 * sizeOf (undefined :: Word64LE)
  alignment _ = alignment  (undefined :: Word64LE)

  peek ptr = runParser cptr parseSalt
    where parseSalt = Salt <$> parseStorable
                           <*> parseStorable               
          cptr      = castPtr ptr

  poke ptr (Salt s0 s1) = runWrite cptr writeSalt
    where writeSalt     = writeStorable s0
                        <> writeStorable s1
          cptr = castPtr ptr

instance EndianStore Salt where
  load cptr = runParser cptr parseSalt
    where parseSalt = Salt <$> parse
                           <*> parse
                           
  store cptr (Salt s0 s1) = runWrite cptr writeSalt
    where writeSalt = write s0
                   <> write s1
                     
instance Primitive BLAKE2B where
  blockSize _ =  roundFloor $ BITS (1024 :: Int)-- roundFloor
  {-# INLINE blockSize #-}
  data Cxt BLAKE2B = BLAKE2BCxt BLAKE2B Salt (BITS Word64) deriving (Eq, Show)
  
instance SafePrimitive BLAKE2B

instance HasPadding BLAKE2B where
  maxAdditionalBlocks _ = 1
  padLength = blake2PadLength
  padding   = blake2Padding

instance Default (Cxt BLAKE2B) where
  def = let
          blake = BLAKE2B  0x6a09e667f3bcc908
                           0xbb67ae8584caa73b
                           0x3c6ef372fe94f82b
                           0xa54ff53a5f1d36f1
                           0x510e527fade682d1
                           0x9b05688c2b3e6c1f
                           0x1f83d9abfb41bd6b
                           0x5be0cd19137e2179
        in
            BLAKE2BCxt blake def 0

instance Default Salt where
  def = Salt 0 0
