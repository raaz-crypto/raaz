{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}

{-|

This module exposes the `SHA1` hash constructor. You would hardly need
to import the module directly as you would want to treat the `SHA1`
type as an opaque type for type safety. This module is exported only
for special uses like writing a test case or defining a binary
instance etc.

-}
module Raaz.Hash.Sha1.Type
       ( SHA1(..)
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

-- | The SHA1 hash value.
data SHA1 = SHA1 {-# UNPACK #-} !(BE Word32)
                 {-# UNPACK #-} !(BE Word32)
                 {-# UNPACK #-} !(BE Word32)
                 {-# UNPACK #-} !(BE Word32)
                 {-# UNPACK #-} !(BE Word32) deriving (Show, Typeable)

-- | Timing independent equality testing.
instance Eq SHA1 where
  (==) (SHA1 g0 g1 g2 g3 g4) (SHA1 h0 h1 h2 h3 h4) =   xor g0 h0
                                                   .|. xor g1 h1
                                                   .|. xor g2 h2
                                                   .|. xor g3 h3
                                                   .|. xor g4 h4
                                                   == 0

instance HasName SHA1

instance Storable SHA1 where
  sizeOf    _ = 5 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))
  peek ptr = runParser cptr parseSHA1
    where parseSHA1 = SHA1 <$> parseStorable
                           <*> parseStorable
                           <*> parseStorable
                           <*> parseStorable
                           <*> parseStorable
          cptr = castPtr ptr

  poke ptr (SHA1 h0 h1 h2 h3 h4) =  runWrite cptr writeSHA1
    where writeSHA1 =  writeStorable h0
                    <> writeStorable h1
                    <> writeStorable h2
                    <> writeStorable h3
                    <> writeStorable h4
          cptr = castPtr ptr

instance EndianStore SHA1 where
  load cptr = runParser cptr parseSHA1
    where parseSHA1 = SHA1 <$> parse
                           <*> parse
                           <*> parse
                           <*> parse
                           <*> parse

  store cptr (SHA1 h0 h1 h2 h3 h4) =  runWrite cptr writeSHA1
    where writeSHA1 =  write h0
                    <> write h1
                    <> write h2
                    <> write h3
                    <> write h4

instance Primitive SHA1 where
  blockSize _ = BYTES 64
  {-# INLINE blockSize #-}
  type Key SHA1 = SHA1

instance SafePrimitive SHA1

instance HasPadding SHA1 where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 8
  padding   = shaPadding   8
