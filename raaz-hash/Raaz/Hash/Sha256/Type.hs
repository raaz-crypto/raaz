{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Raaz.Hash.Sha256.Type
       ( SHA256(..)
       , Cxt(SHA256Cxt)
       ) where

import Control.Applicative ( (<$>), (<*>) )
import Data.Bits           ( xor, (.|.)   )
import Data.Default
import Data.Monoid
import Data.Word
import Data.Typeable       ( Typeable     )
import Foreign.Ptr         ( castPtr      )
import Foreign.Storable    ( Storable(..) )

import Raaz.Core.Parse.Unsafe
import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Core.Write.Unsafe

import Raaz.Hash.Sha.Util

----------------------------- SHA256 -------------------------------------------

-- | The Sha256 hash value. Used in implementation of Sha224 as well.
data SHA256 = SHA256 {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32) deriving (Show, Typeable)

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

instance HasName SHA256

instance Digestible SHA256 where
  type Digest SHA256 = SHA256
  toDigest (SHA256Cxt h) = h

instance Storable SHA256 where
  sizeOf    _ = 8 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))

  peek ptr = runParser cptr parseSHA256
    where parseSHA256 = SHA256 <$> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
          cptr = castPtr ptr

  poke ptr (SHA256 h0 h1 h2 h3 h4 h5 h6 h7) =  runWrite cptr writeSHA256
    where writeSHA256 =  writeStorable h0
                      <> writeStorable h1
                      <> writeStorable h2
                      <> writeStorable h3
                      <> writeStorable h4
                      <> writeStorable h5
                      <> writeStorable h6
                      <> writeStorable h7
          cptr = castPtr ptr

instance EndianStore SHA256 where
  load cptr = runParser cptr parseSHA256
    where parseSHA256 = SHA256 <$> parse
                               <*> parse
                               <*> parse
                               <*> parse
                               <*> parse
                               <*> parse
                               <*> parse
                               <*> parse

  store cptr (SHA256 h0 h1 h2 h3 h4 h5 h6 h7) =  runWrite cptr writeSHA256
    where writeSHA256 =  write h0
                      <> write h1
                      <> write h2
                      <> write h3
                      <> write h4
                      <> write h5
                      <> write h6
                      <> write h7

instance Primitive SHA256 where
  blockSize _ = BYTES 64
  {-# INLINE blockSize #-}
  newtype Cxt SHA256 = SHA256Cxt SHA256 deriving (Eq, Show, Storable)

instance SafePrimitive SHA256

instance HasPadding SHA256 where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 8
  padding   = shaPadding   8

instance Default (Cxt SHA256) where
  def = SHA256Cxt $ SHA256 0x6a09e667
                          0xbb67ae85
                          0x3c6ef372
                          0xa54ff53a
                          0x510e527f
                          0x9b05688c
                          0x1f83d9ab
                          0x5be0cd19
