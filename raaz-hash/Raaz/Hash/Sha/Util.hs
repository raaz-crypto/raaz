module Raaz.Hash.Sha.Util
       ( shaPadLength, shaPadding
       , blakePadLength, blakePadding
       , blake2bPadLength, blake2bPadding
       , blake2sPadLength, blake2sPadding
       ) where

import Data.ByteString      hiding  ( length            )
import Data.Monoid                  ( (<>)              )
import Data.Word
import Data.Bits
import Prelude              hiding  ( length, replicate )

import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Core.Util.ByteString ( length )

firstPadByte :: Word8
firstPadByte = 128

-- | This computes the padding length for the sha family of
-- hashes.
shaPadLength :: Primitive prim
          => BYTES Int      -- ^ The bytes need to encode the
                            -- message length
          -> prim           -- ^ The primitive
          -> BITS Word64    -- ^ The length of the message
          -> BYTES Int
{-# INLINEABLE shaPadLength #-}
shaPadLength lenSize h l
  | r >= lenSize + 1 = r
  | otherwise        = r + blockSize h
  where lb :: BYTES Int
        lb = roundFloor l `rem` blockSize h
        r  = blockSize h - lb

-- | This computes the padding for the sha family of hashes.
shaPadding :: Primitive prim
           => BYTES Int      -- ^ The bytes need to encode the
                             -- message length
           -> prim           -- ^ The primitive
           -> BITS Word64  -- ^ The length of the message
           -> ByteString
{-# INLINEABLE shaPadding #-}
shaPadding lenSize prim lBits =  singleton firstPadByte
                              <> replicate zeros 0
                              <> lPad
     where pLen        = shaPadLength lenSize prim lBits
           lPad        = toByteString l
           l           = roundFloor lBits :: BITS Word64BE
           BYTES zeros = pLen - length lPad - 1

-- | Padding length for a 64-bit length appended hash like Blake256
blakePadLength :: Primitive prim
                 => BYTES Int      -- ^ The bytes need to encode the
                                   -- message length
                 -> prim           -- ^ The primitive
                 -> BITS Word64    -- ^ The length of the message
                 -> BYTES Int
{-# INLINE blakePadLength #-}
blakePadLength lenSize h l
  | r >= lenSize + 1 = r
  | otherwise        = r + blockSize h
  where lb :: BYTES Int
        lb    = roundFloor l `rem` blockSize h
        r     = blockSize h - lb

-- | Padding string for a 64-bit length appended hash like Blake256
blakePadding :: Primitive prim
               => BYTES Int      -- ^ The bytes need to encode the
                                 -- message length
               -> prim           -- ^ The primitive
               -> BITS Word64    -- ^ The length of the message
               -> ByteString
{-# INLINE blakePadding #-}
blakePadding lenSize prim lBits =  prefix
                                <> lPad
    where prefix | pLen == lenSize + 1 = singleton $ 0x80 `xor` 0x01
                 | otherwise =  singleton 0x80
                             <> zbs
                             <> singleton 0x01
          pLen      = blakePadLength lenSize prim lBits :: BYTES Int
          lPad      = toByteString l
          l         = roundFloor lBits :: BITS Word64BE
          numzero   = fromIntegral $ pLen - length lPad - 2
          zbs       = replicate numzero 0


blake2bPadLength :: Primitive prim
                 => prim
                 -> BITS Word64
                 -> BYTES Int
{-# INLINE blake2bPadLength #-}
blake2bPadLength h l
  | lb == 0 = 0           
  | otherwise = r      
  where lb :: BYTES Int
        lb =  roundFloor l `rem` blockSize h
        r  = blockSize h - lb

blake2bPadding :: Primitive prim
               => prim
               -> BITS Word64
               -> ByteString
{-# INLINE blake2bPadding #-}
blake2bPadding prim lbits
 | pLen == 0 = replicate 0 0
 | otherwise = replicate numzero 0
 where  pLen    = blake2bPadLength prim lbits :: BYTES Int
        numzero = fromIntegral pLen


blake2sPadLength :: Primitive prim
                 => prim
                 -> BITS Word64
                 -> BYTES Int
{-# INLINE blake2sPadLength #-}
blake2sPadLength h l
  | lb == 0 = 0           
  | otherwise = r      
  where lb :: BYTES Int
        lb =  roundFloor l `rem` blockSize h
        r  = blockSize h - lb

blake2sPadding :: Primitive prim
               => prim
               -> BITS Word64
               -> ByteString
{-# INLINE blake2sPadding #-}
blake2sPadding prim lbits
 | pLen == 0 = replicate 0 0
 | otherwise = replicate numzero 0
 where  pLen    = blake2bPadLength prim lbits :: BYTES Int
        numzero = fromIntegral pLen