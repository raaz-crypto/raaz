{-|

Generic cryptographic block primtives and their implementations. This
module exposes low-level generic code used in the raaz system. Most
likely, one would not need to stoop so low and it might be better to
use a more high level interface.

-}

{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE MultiParamTypeClasses       #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
{-# LANGUAGE FlexibleContexts            #-}
{-# LANGUAGE CPP                         #-}
{-# LANGUAGE ConstraintKinds             #-}
{-# LANGUAGE ExistentialQuantification   #-}
{-# LANGUAGE DataKinds                   #-}

module Raaz.Core.Primitive
       ( -- * Primtives and their implementations.
         Primitive(..), blockSize
       , BLOCKS, blocksOf
       ) where

#if !MIN_VERSION_base(4,8,0)
import Data.Monoid  -- Import only when base < 4.8.0
#endif

#if !MIN_VERSION_base(4,11,0)
import Data.Semigroup
#endif

import Data.Proxy
import GHC.TypeLits
import Prelude

import Raaz.Core.Types

----------------------- A primitive ------------------------------------


-- | The type class that captures an abstract block cryptographic
-- primitive.
class KnownNat (BlockSize p) => Primitive p where

  -- | Bulk cryptographic primitives like hashes, ciphers etc often
  -- acts on blocks of data. The size of the block is captured by the
  -- associated type `BlockSize`.
  type BlockSize p :: Nat

  -- | The key associated with primitive. In the setting of the raaz
  -- library keys are "inputs" that are required to start processing.
  -- Often primitives like ciphers have a /secret key/ together with
  -- an additional nounce/IV. This type denotes not just the secret
  -- key par but the nounce too.
  --
  -- Primitives like hashes that do not require a key should have this
  -- type defined as `()`.

  type Key p :: *

  -- | Many primitives produce additional message digest after
  -- processing the input, think of cryptographic hashes, AEAD
  -- primitives etc. This associated type captures such additional
  -- data produced by the primitive.
  type Digest p :: *



-- | The block size.
blockSize :: Primitive prim => Proxy prim -> BYTES Int
blockSize  = toEnum . fromEnum . natVal . getBlockSizeProxy
  where getBlockSizeProxy ::  Proxy prim -> Proxy (BlockSize prim)
        getBlockSizeProxy _ = Proxy
------------------- Type safe lengths in units of block ----------------

-- | Type safe message length in units of blocks of the primitive.
-- When dealing with buffer lengths for a primitive, it is often
-- better to use the type safe units `BLOCKS`. Functions in the raaz
-- package that take lengths usually allow any type safe length as
-- long as they can be converted to bytes. This can avoid a lot of
-- tedious and error prone length calculations.
newtype BLOCKS p = BLOCKS {unBLOCKS :: Int}
                 deriving (Show, Eq, Ord, Enum)

instance Semigroup (BLOCKS p) where
  (<>) x y = BLOCKS $ unBLOCKS x + unBLOCKS y
instance Monoid (BLOCKS p) where
  mempty   = BLOCKS 0
  mappend  = (<>)

instance Primitive p => LengthUnit (BLOCKS p) where
  inBytes p@(BLOCKS x) = scale * blockSize primProxy
    where scale = BYTES x
          primProxy = getProxy p
          getProxy :: BLOCKS p -> Proxy p
          getProxy _ = Proxy

-- | The expression @n `blocksOf` primProxy@ specifies the message
-- lengths in units of the block length of the primitive whose proxy
-- is @primProxy@. This expression is sometimes required to make the
-- type checker happy.
blocksOf :: Int -> Proxy p -> BLOCKS p
blocksOf n _ = BLOCKS n
