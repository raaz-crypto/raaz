{-|

This module exposes the `SHA224` hash constructor. You would hardly
need to import the module directly as you would want to treat the
`SHA224` type as an opaque type for type safety. This module is
exported only for special uses like writing a test case or defining a
binary instance etc.

-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

module Raaz.Hash.Sha224.Type
       ( SHA224(..)
       ) where

import Control.Applicative ( (<$>), (<*>) )
import Data.Bits           ( xor, (.|.)   )
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
import Raaz.Hash.Sha256.Type
import Raaz.Hash.Sha256.Instance ()

----------------------------- SHA224 -------------------------------------------

-- | Sha224 hash value which consist of 7 32bit words.
data SHA224 = SHA224 {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32)
                     {-# UNPACK #-} !(BE Word32) deriving (Show, Typeable)

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

instance HasName SHA224

instance Storable SHA224 where
  sizeOf    _ = 7 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))

  peek ptr = runParser cptr parseSHA224
    where parseSHA224 = SHA224 <$> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
          cptr = castPtr ptr

  poke ptr (SHA224 h0 h1 h2 h3 h4 h5 h6) =  runWrite cptr writeSHA224
    where writeSHA224 =  writeStorable h0
                      <> writeStorable h1
                      <> writeStorable h2
                      <> writeStorable h3
                      <> writeStorable h4
                      <> writeStorable h5
                      <> writeStorable h6
          cptr = castPtr ptr

instance EndianStore SHA224 where
  load cptr = runParser cptr parseSHA224
    where parseSHA224 = SHA224 <$> parse
                               <*> parse
                               <*> parse
                               <*> parse
                               <*> parse
                               <*> parse
                               <*> parse

  store cptr (SHA224 h0 h1 h2 h3 h4 h5 h6) =  runWrite cptr writeSHA224
    where writeSHA224 =  write h0
                      <> write h1
                      <> write h2
                      <> write h3
                      <> write h4
                      <> write h5
                      <> write h6

instance Primitive SHA224 where
  blockSize _ = BYTES 64
  {-# INLINE blockSize #-}
  type Key SHA224 = SHA256

instance SafePrimitive SHA224

instance HasPadding SHA224 where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 8
  padding   = shaPadding   8
