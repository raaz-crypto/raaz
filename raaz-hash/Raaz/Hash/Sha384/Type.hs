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
       ) where

import Control.Applicative ( (<$>), (<*>) )
import Data.Bits           ( xor, (.|.)   )
import Data.Monoid
import Data.Word
import Data.Typeable       ( Typeable     )
import Foreign.Ptr         ( castPtr      )
import Foreign.Storable    ( Storable(..) )

import Raaz.Core.Memory
import Raaz.Core.Parse.Unsafe
import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Core.Write.Unsafe

import Raaz.Hash.Sha.Util
import Raaz.Hash.Sha512.Type ( SHA512(..) )


----------------------------- SHA384 -------------------------------------------

-- | The Sha384 hash value.
data SHA384 = SHA384 {-# UNPACK #-} !(BE Word64)
                     {-# UNPACK #-} !(BE Word64)
                     {-# UNPACK #-} !(BE Word64)
                     {-# UNPACK #-} !(BE Word64)
                     {-# UNPACK #-} !(BE Word64)
                     {-# UNPACK #-} !(BE Word64) deriving (Show, Typeable)

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

instance HasName SHA384

instance Storable SHA384 where
  sizeOf    _ = 6 * sizeOf (undefined :: (BE Word64))
  alignment _ = alignment  (undefined :: (BE Word64))

  peek ptr = runParser cptr parseSHA384
    where parseSHA384 = SHA384 <$> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
                               <*> parseStorable
          cptr = castPtr ptr

  poke ptr (SHA384 h0 h1 h2 h3 h4 h5) =  runWrite cptr writeSHA384
    where writeSHA384 =  writeStorable h0
                      <> writeStorable h1
                      <> writeStorable h2
                      <> writeStorable h3
                      <> writeStorable h4
                      <> writeStorable h5
          cptr = castPtr ptr

instance EndianStore SHA384 where
  load cptr = runParser cptr parseSHA384
    where parseSHA384 = SHA384 <$> parse
                               <*> parse
                               <*> parse
                               <*> parse
                               <*> parse
                               <*> parse

  store cptr (SHA384 h0 h1 h2 h3 h4 h5) =  runWrite cptr writeSHA384
    where writeSHA384 =  write h0
                      <> write h1
                      <> write h2
                      <> write h3
                      <> write h4
                      <> write h5

instance Primitive SHA384 where
  blockSize _ = BYTES 128
  {-# INLINE blockSize #-}
  type Key SHA384 = SHA512

instance SafePrimitive SHA384

instance HasPadding SHA384 where
  maxAdditionalBlocks _ = 1
  padLength = shaPadLength 16
  padding   = shaPadding   16
