{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

-- |
--
-- Module      : Raaz.Primitive.Blake2.Internal
-- Description : Internal modules for Blake2 hashes.
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
module Raaz.Primitive.Blake2.Internal
       ( -- * The blake2 types
         Blake2b, Blake2s
       , Blake2bMem, Blake2sMem
       , blake2Pad
       ) where

import           Data.Vector.Unboxed        ( Unbox )
import           Foreign.Storable           ( Storable       )

import           Raaz.Core
import           Raaz.Primitive.HashMemory
import           Raaz.Primitive.Keyed.Internal

----------------------------- The blake2 type ---------------------------------

-- | The Blake2 type.
newtype Blake2 w = Blake2 (Tuple 8 w)
               deriving (Eq, Equality, Storable, EndianStore)

instance ( Unbox w
         , EndianStore w
         ) => Primitive (Blake2 w) where
  type WordType      (Blake2 w) = w
  type WordsPerBlock (Blake2 w) = 16

instance (Unbox w, EndianStore w) => Encodable (Blake2 w)

instance (EndianStore w, Unbox w) => IsString (Blake2 w) where
  fromString = fromBase16

instance (EndianStore w, Unbox w) => Show (Blake2 w) where
  show =  showBase16

-- | The Blake2b hash type.
type Blake2b = Blake2 (LE Word64)

-- | The Blake2s hash type.
type Blake2s = Blake2 (LE Word32)

keyLength :: (Storable prim, Num b) => Proxy prim -> BYTES Int -> b
keyLength proxy len
  | len > tLen = fromIntegral tLen
  | otherwise  = fromIntegral len
  where tLen = sizeOf proxy

instance KeyedHash Blake2b where
  hashInit len = Blake2 $ unsafeFromList [ 0x6a09e667f3bcc908 `xor` iv0
                                         , 0xbb67ae8584caa73b
                                         , 0x3c6ef372fe94f82b
                                         , 0xa54ff53a5f1d36f1
                                         , 0x510e527fade682d1
                                         , 0x9b05688c2b3e6c1f
                                         , 0x1f83d9abfb41bd6b
                                         , 0x5be0cd19137e2179
                                         ]
    where len8 = keyLength (Proxy :: Proxy Blake2b) len
          iv0  = 0x01010040 .|. shiftL len8 8

instance KeyedHash Blake2s where
  hashInit len =  Blake2 $ unsafeFromList [ 0x6a09e667 `xor` iv0
                                          , 0xbb67ae85
                                          , 0x3c6ef372
                                          , 0xa54ff53a
                                          , 0x510e527f
                                          , 0x9b05688c
                                          , 0x1f83d9ab
                                          , 0x5be0cd19
                                          ]
    where len8 = keyLength (Proxy :: Proxy Blake2s) len
          iv0  = 0x01010020  .|. shiftL len8 8


---------------------------------- Memory element for Blake2b -----------------------
-- | The memory element for blake2b hash.
type Blake2bMem = HashMemory128 Blake2b

-- | The memory element for blake2s hash.
type Blake2sMem = HashMemory64 Blake2s

instance Initialisable Blake2bMem () where
  initialise _ = initialise (hashInit 0 :: Blake2b)

instance Initialisable Blake2sMem () where
  initialise _ = initialise (hashInit 0 :: Blake2s)

----------------------- Padding for Blake code ------------------------------

-- | The generic blake2 padding algorithm. We pad the message with
-- just enough zero's to make it a multiple of the block size. The
-- exception is the empty message which should generate a single block
-- of zeros.
--
blake2Pad :: Primitive prim
          => Proxy prim  -- ^ the primitive (Blake2b or Blake2s).
          -> BYTES Int   -- ^ length of the message
          -> WriteTo
blake2Pad primProxy m
  | m == 0    = writeBytes 0 $ blocksOf 1 primProxy -- empty message
  | otherwise = padWrite 0 (blocksOf 1 primProxy) $ skip m
