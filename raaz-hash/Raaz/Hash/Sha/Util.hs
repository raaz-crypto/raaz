module Raaz.Hash.Sha.Util
       ( shaPadLength, shaPadding
       ) where

import Data.ByteString      hiding  ( length            )
import Data.Monoid                  ( (<>)              )
import Data.Word
import Prelude              hiding  ( length, replicate )

import Raaz.Primitives
import Raaz.Types
import Raaz.Util.ByteString ( length   )

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
        lb = cryptoCoerce l `rem` blockSize h
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
           l           = cryptoCoerce lBits :: BITS Word64BE
           BYTES zeros = pLen - length lPad - 1
