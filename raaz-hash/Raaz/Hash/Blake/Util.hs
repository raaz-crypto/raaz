module Raaz.Hash.Blake.Util
       ( blakePadLength,blakePadding
       ) where

import Data.ByteString              ( ByteString, singleton)
import Data.Monoid                  ( (<>)              )
import Data.Word
import Prelude              hiding  ( length, replicate )

import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Core.Util.ByteString    ( replicate )

-- | The padding used by blake is the following:
--
-- 1. Length extend the message so that the length is 447 mod 512.
-- This is done by adding a 1 bit and as many zeros so that the length
-- is 447 mod 512. This is followed by adding the length of the message
-- in 64bit little endian.

-- | Padding length for a 64-bit length appended hash like Blake256.
blakePadLength :: Primitive prim
               => BYTES Int      -- ^ size of the length encoding.
               -> prim
               -> BITS Word64    -- ^ The length of the message
               -> BYTES Int
{-# INLINE blakePadLength #-}

blakePadLength lSize prim lBits
  | r >= lSize + 1 = r
  | otherwise      = r + blkSz
  where l     = bitsQuot lBits `rem` blkSz
        r     = blkSz  - l
        blkSz = blockSize prim
-- | Padding string Blake256
blakePadding :: Primitive prim
             => BYTES Int
             -> prim
             -> BITS Word64    -- ^ The length of the message
             -> ByteString
{-# INLINE blakePadding #-}
blakePadding lSize prim lBits
  | pLen == lSize + 1 =  singleton 0x81  <> lPad
  | otherwise         =  singleton 0x80
                         <> replicate zeros 0
                         <> singleton 0x01
                         <> lPad
  where pLen    = blakePadLength lSize prim lBits
        zeros   = pLen - lSize - 2
        -- The length pad
        l       = cryptoCoerce lBits :: BITS (BE Word64)
        lPad    = msb <> toByteString l
        msb     = replicate (lSize - 8) 0
