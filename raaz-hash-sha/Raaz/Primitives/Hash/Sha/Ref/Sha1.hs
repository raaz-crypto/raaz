{-|

This module gives the reference implementation of the sha1
hash. Depending on your platform there might be a more efficient
implementation. So you /should not/ be using this code in production.

-}
       
{-# LANGUAGE CPP             #-}
{-# LANGUAGE TemplateHaskell #-}

module Raaz.Primitives.Hash.Sha.Ref.Sha1
       ( sha1Compress
       ) where

import Control.Monad
import Data.Bits
import Raaz.Types
import Raaz.Util.Ptr
import Raaz.Util.TH


import Raaz.Primitives.Hash.Sha(SHA1(..))

initSha1 :: SHA1
initSha1 =  SHA1 0x67452301
                 0xefcdab89
                 0x98badcfe
                 0x10325476
                 0xc3d2e1f0


-- | The round constants for SHA1 hash
k :: Int -> Word32BE  -- ^ The round constants
{-# INLINE k #-}      -- In INLINE we trust (for performance)
k i | i <= 19   = 0x5a827999
    | i <= 39   = 0x6ed9eba1
    | i <= 59   = 0x8f1bbcdc
    | i <= 79   = 0xca62c1d6
    | otherwise = error "unthinkable happend with K_t in SHA1 reference"
                  
-- | The round functions.
f :: Int -> Word32BE -> Word32BE -> Word32BE -> Word32BE
{-# INLINE f #-}    -- In INLINE we trust (for performance)
f i x y z | i <= 19   = (x .&. y) `xor` (complement x .&. z)
          | i <= 39   = x `xor` y `xor` z
          | i <= 59   = (x .&. y) `xor` (y .&. z) `xor` (z .&. x)
          | i <= 79   = x `xor` y `xor` z
          | otherwise = error "unthinkable has happened f_t in SHA1 reference"
                      

sha1Compress :: SHA1
             -> CryptoPtr
             -> IO SHA1
sha1Compress (SHA1 h0 h1 h2 h3 h4) cptr = round h0 h1 h2 h3 h4 <$> load cptr
       <*> loadFromIndex cptr 1
       <*> loadFromIndex cptr 2
       <*> loadFromIndex cptr 3
       <*> loadFromIndex cptr 4
       <*> loadFromIndex cptr 5
       <*> loadFromIndex cptr 6
       <*> loadFromIndex cptr 7
       <*> loadFromIndex cptr 8
       <*> loadFromIndex cptr 9
       <*> loadFromIndex cptr 10
       <*> loadFromIndex cptr 11
       <*> loadFromIndex cptr 12
       <*> loadFromIndex cptr 13
       <*> loadFromIndex cptr 14
       <*> loadFromIndex cptr 15
  
   where m i w0 w1 w2 w3 w4 w5 w6 w7 w8 w10 w11 w12 w13 w14 w15 
         m 0 = 
                 
                 
-}               
{-
-- | Compresses one block.
sha1Compress :: SHA1
             -> CryptoPtr
             -> IO SHA1
sha1Compress (SHA1 h0 h1 h2 h3 h4) cptr = do
         w0  <- loadFromIndex cptr 0
         w1  <- loadFromIndex cptr 1
         w2  <- loadFromIndex cptr 2
         w3  <- loadFromIndex cptr 3
         w4  <- loadFromIndex cptr 4
         w5  <- loadFromIndex cptr 5
         w6  <- loadFromIndex cptr 6
         w7  <- loadFromIndex cptr 7
         w8  <- loadFromIndex cptr 8
         w9  <- loadFromIndex cptr 9
         w10 <- loadFromIndex cptr 10
         w11 <- loadFromIndex cptr 11
         w12 <- loadFromIndex cptr 12
         w13 <- loadFromIndex cptr 13
         w14 <- loadFromIndex cptr 14
         w15 <- loadFromIndex cptr 15
  return $ SHA1 (h0 + a79) (h1 h2 h3 h4
      where $(forM [0..79] $ \i -> signature "w" ''Word32BE [i])
                 
  where 
-}