{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash.Blake2s.Type
       ( BLAKE2S(..)
       , Salt(..)       
       , Cxt(BLAKE2SCxt)
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

------------------------------------BLAKE2S----------------------------------

-- | The Blake2S hash value.
data BLAKE2S = BLAKE2S   {-# UNPACK #-} !Word32LE
                         {-# UNPACK #-} !Word32LE
                         {-# UNPACK #-} !Word32LE
                         {-# UNPACK #-} !Word32LE
                         {-# UNPACK #-} !Word32LE
                         {-# UNPACK #-} !Word32LE
                         {-# UNPACK #-} !Word32LE
                         {-# UNPACK #-} !Word32LE deriving (Show, Typeable)

-- | The Blake2S salt value.
data Salt = Salt {-# UNPACK #-} !Word32LE
                 {-# UNPACK #-} !Word32LE deriving (Show, Typeable)



-- | Timing independent equality testing for Blake2S
instance Eq BLAKE2S where
  (==) (BLAKE2S g0 g1 g2 g3 g4 g5 g6 g7) (BLAKE2S h0 h1 h2 h3 h4 h5 h6 h7)
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
      

instance HasName BLAKE2S

instance Digestible BLAKE2S where
  type Digest BLAKE2S = BLAKE2S
  toDigest (BLAKE2SCxt b _ _) = b

instance Storable BLAKE2S where
  sizeOf    _ = 8 * sizeOf (undefined :: Word32LE)
  alignment _ = alignment  (undefined :: Word32LE)

  peek ptr = runParser cptr parseBLAKE2S
    where parseBLAKE2S = BLAKE2S   <$> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
                                   <*> parseStorable
          cptr = castPtr ptr

  poke ptr (BLAKE2S h0 h1 h2 h3 h4 h5 h6 h7) = runWrite cptr writeBLAKE2S
    where writeBLAKE2S  =  writeStorable h0
                        <> writeStorable h1
                        <> writeStorable h2
                        <> writeStorable h3
                        <> writeStorable h4
                        <> writeStorable h5
                        <> writeStorable h6
                        <> writeStorable h7
          cptr = castPtr ptr

instance Storable (Cxt BLAKE2S) where
  sizeOf    _ = 11 * sizeOf (undefined :: Word32LE)
  alignment _ = alignment   (undefined :: Word32LE)

  peek ptr = runParser cptr parseBLAKE2SCxt
    where parseBLAKE2SCxt = BLAKE2SCxt  <$> parseStorable
                                         <*> parseStorable
                                         <*> parseStorable
          cptr = castPtr ptr

  poke ptr (BLAKE2SCxt (BLAKE2S h0 h1 h2 h3 h4 h5 h6 h7)
                        (Salt s0 s1)
                        t
           ) = runWrite cptr writeBLAKE2SCxt
    where writeBLAKE2SCxt  =  writeStorable h0
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

instance EndianStore BLAKE2S where
  load cptr = runParser cptr parseBLAKE2S
    where parseBLAKE2S = BLAKE2S   <$> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse
                                   <*> parse

  store cptr (BLAKE2S h0 h1 h2 h3 h4 h5 h6 h7) = runWrite cptr writeBLAKE2S
    where writeBLAKE2S  =  write h0
                        <> write h1
                        <> write h2
                        <> write h3
                        <> write h4
                        <> write h5
                        <> write h6
                        <> write h7

instance Storable Salt where
  sizeOf    _ = 2 * sizeOf (undefined :: Word32LE)
  alignment _ = alignment  (undefined :: Word32LE)

  peek ptr = runParser cptr parseSalt
    where parseSalt = Salt <$> parseStorable
               <*> parseStorable               
          cptr = castPtr ptr

  poke ptr (Salt s0 s1) = runWrite cptr writeSalt
    where writeSalt = writeStorable s0
           <> writeStorable s1           
          cptr = castPtr ptr

instance EndianStore Salt where
  load cptr = runParser cptr parseSalt
    where parseSalt = Salt <$> parse
                           <*> parse                           

  store cptr (Salt s0 s1) = runWrite cptr writeSalt
    where writeSalt = write s0
                   <> write s1                  

instance Primitive BLAKE2S where
  blockSize _ = BYTES 64
  {-# INLINE blockSize #-}
  data Cxt BLAKE2S = BLAKE2SCxt BLAKE2S Salt (BITS Word64) deriving (Eq, Show)
  

instance SafePrimitive BLAKE2S

instance HasPadding BLAKE2S where
  maxAdditionalBlocks _ = 1
  padLength = blake2PadLength
  padding   = blake2Padding

instance Default (Cxt BLAKE2S) where
  def = let
          blake = BLAKE2S  0x6a09e667
                           0xbb67ae85
                           0x3c6ef372
                           0xa54ff53a
                           0x510e527f
                           0x9b05688c
                           0x1f83d9ab
                           0x5be0cd19          
        in
            BLAKE2SCxt blake def 0

instance Default Salt where
  def = Salt 0 0
