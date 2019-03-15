{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

-- | Internal types and function for blake2 hashes.
module Raaz.Primitive.Blake2.Internal
       ( -- * The blake2 types
         Blake2b, Blake2s
       , Blake2bMem, Blake2sMem
       , blake2Pad
       ) where

import           Control.Monad.IO.Class
import           Data.Bits
import           Data.Proxy
import           Data.String
import           Data.Word                  ( Word64, Word32 )
import           Foreign.Storable           ( Storable(..)   )
import           Prelude      hiding        ( zipWith        )

import           Raaz.Core
import           Raaz.Primitive.HashMemory
import           Raaz.Primitive.Keyed.Internal

----------------------------- The blake2 type ---------------------------------

-- | The Blake2 type.
newtype Blake2 w = Blake2 (Tuple 8 w)
               deriving (Eq, Equality, Storable, EndianStore)

-- | Word type for Blake2b
type Word2b = LE Word64

-- | Word type for Blake2s
type Word2s = LE Word32

-- | The Blake2b hash type.
type Blake2b = Blake2 Word2b

-- | The Blake2s hash type.
type Blake2s = Blake2 Word2s

instance Encodable Blake2b
instance Encodable Blake2s


instance IsString Blake2b where
  fromString = fromBase16

instance IsString Blake2s where
  fromString = fromBase16

instance Show Blake2b where
  show =  showBase16

instance Show Blake2s where
  show =  showBase16

instance Primitive Blake2b where
  type BlockSize Blake2b      = 128

instance Primitive Blake2s where
  type BlockSize Blake2s      = 64


keyLength :: (Storable prim, Num b) => Proxy prim -> BYTES Int -> b
keyLength proxy len
  | len > tLen = fromIntegral tLen
  | otherwise  = fromIntegral len
  where tLen = trimLength proxy

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

type Blake2bMem = HashMemory128 Blake2b
type Blake2sMem = HashMemory64 Blake2s

instance Initialisable Blake2bMem () where
  initialise _ = initialise $ (hashInit 0 :: Blake2b)

instance Initialisable Blake2sMem () where
  initialise _ = initialise $ (hashInit 0 :: Blake2s)

----------------------- Padding for Blake code ------------------------------

-- | The generic blake2 padding algorithm.
blake2Pad :: (Primitive prim, MonadIO m)
          => Proxy prim  -- ^ the primitive (Blake2b or Blake2s).
          -> BYTES Int   -- ^ length of the message
          -> WriteM m
blake2Pad primProxy = padWrite 0 (blocksOf 1 primProxy) . skip
