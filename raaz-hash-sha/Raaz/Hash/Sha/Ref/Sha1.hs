{-|

This module gives the reference implementation of the sha1
hash. Depending on your platform there might be a more efficient
implementation. So you /should not/ be using this code in production.

-}

{-# LANGUAGE TypeFamilies      #-}
{-# LANGUAGE FlexibleInstances #-}
module Raaz.Hash.Sha.Ref.Sha1
       ( SHA1(..)
       ) where

import Data.Bits
import qualified Data.ByteString as B
import Data.Word
import Foreign.Ptr
import Foreign.Storable

import Raaz.Types
import Raaz.Primitives
import Raaz.Hash

-- | The SHA1 hashing algorithm.
data SHA1 = SHA1

instance BlockPrimitive SHA1 where
  blockSize _ = BYTES 64


instance Compressor SHA1 where
  type Cxt SHA1 = Hash SHA1

  maxAdditionalBlocks _ = 1

  padLength sha1 l | r <= 56   = r
                   | otherwise = r + blksz
    where lb    = cryptoCoerce l :: BYTES Int
          r     = (lb + 1) `rem` blksz
          blksz = blockSize sha1

  padding sha1 l = B.concat [ B.singleton firstPadByte
                            , B.replicate zeros 0
                            , toByteString lBits
                            ]
     where r      = padLength sha1 l :: BYTES Int
           zeros  = fromIntegral (r - 1 - 8)
           lBits  = cryptoCoerce l :: BITS Word64BE

  unsafePadIt sha1 l pos cptr = return ()
  compress _ cxt _ cptr blks  = return cxt


instance CryptoHash SHA1 where
  data Hash SHA1 = Sha1 {-# UNPACK #-} !Word32BE
                        {-# UNPACK #-} !Word32BE
                        {-# UNPACK #-} !Word32BE
                        {-# UNPACK #-} !Word32BE
                        {-# UNPACK #-} !Word32BE

  startHashCxt _ = Sha1 0x67452301
                        0xefcdab89
                        0x98badcfe
                        0x10325476
                        0xc3d2e1f0

  finaliseHash _ = id



instance Eq (Hash SHA1) where
  (==) (Sha1 g0 g1 g2 g3 g4) (Sha1 h0 h1 h2 h3 h4) =   xor g0 h0
                                                   .|. xor g1 h1
                                                   .|. xor g2 h2
                                                   .|. xor g3 h3
                                                   .|. xor g4 h4
                                                   == 0

instance Storable (Hash SHA1) where
  sizeOf    _ = 5 * sizeOf (undefined :: Word32BE)
  alignment _ = alignment  (undefined :: Word32BE)
  peekByteOff ptr pos = do
    h0 <- peekByteOff ptr pos
    h1 <- peekByteOff ptr (pos + 4)
    h2 <- peekByteOff ptr (pos + 8)
    h3 <- peekByteOff ptr (pos + 12)
    h4 <- peekByteOff ptr (pos + 16)
    return $ Sha1 h0 h1 h2 h3 h4
  pokeByteOff ptr pos (Sha1 h0 h1 h2 h3 h4) =  pokeByteOff ptr pos        h0
                                            >> pokeByteOff ptr (pos + 4)  h1
                                            >> pokeByteOff ptr (pos + 8)  h2
                                            >> pokeByteOff ptr (pos + 12) h3
                                            >> pokeByteOff ptr (pos + 16) h4

instance CryptoStore (Hash SHA1) where
  load cptr = do h0 <- load cptr
                 h1 <- load $ plusPtr cptr 4
                 h2 <- load $ plusPtr cptr 8
                 h3 <- load $ plusPtr cptr 12
                 h4 <- load $ plusPtr cptr 16
                 return $ Sha1 h0 h1 h2 h3 h4


  store cptr (Sha1 h0 h1 h2 h3 h4) =  store cptr                h0
                                   >> store (cptr `plusPtr` 4)  h1
                                   >> store (cptr `plusPtr` 8)  h2
                                   >> store (cptr `plusPtr` 12) h3
                                   >> store (cptr `plusPtr` 16) h4


firstPadByte :: Word8
firstPadByte = 127
