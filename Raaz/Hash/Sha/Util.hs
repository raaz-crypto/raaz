{-# LANGUAGE TypeFamilies               #-}

module Raaz.Hash.Sha.Util
       ( shaPadLength, shaPadding
       ) where

import Data.ByteString              ( ByteString, singleton )
import Data.Monoid                  ( (<>)      )
import Data.Word

import Prelude              hiding  ( length, replicate )


import Raaz.Core.Primitives
import Raaz.Core.Types
import Raaz.Core.Util.ByteString ( replicate )

-- The padding used by sha family of hashes is as follows
--
-- 1. append a 1 to the bit stream
--
-- 2. In the current block if there is enough space for storing the
-- message length, then append the message length in big endian at the
-- end of the block and fill the rest with zeros. Otherwise have an
-- extra block and do the above.
--
-- Since we handle messages in bytes instead of bits we invariably
-- have to append first a byte with 1 as the MSB and follow the above
-- procedure.


firstPadByte :: Word8
firstPadByte = 0x80

-- | This computes the padding length for the sha family of hashes.
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
  where lb = bitsQuot l `rem` blockSize h
        r  = blockSize h - lb

-- | This computes the padding for the sha family of hashes.
shaPadding :: Primitive prim
           => BYTES Int      -- ^ The bytes need to encode the
                             -- message length
           -> prim           -- ^ The primitive
           -> BITS Word64    -- ^ The length of the message
           -> ByteString
{-# INLINEABLE shaPadding #-}
shaPadding lenSize prim lBits =  singleton firstPadByte
                              <> replicate zeros 0
                              <> lPad
     where pLen  = shaPadLength lenSize prim lBits
           lPad  = toByteString l
           l     = cryptoCoerce lBits :: BITS (BE Word64)
           zeros = pLen - 1 - 8
