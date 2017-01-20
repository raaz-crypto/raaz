{-# LANGUAGE CPP                   #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE ConstraintKinds      #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}

-- | This module gives ways to force the alignment of types.
module Raaz.Core.Types.Aligned
  ( -- * Types to force alignment.
    Aligned, unAligned, aligned16Bytes, aligned32Bytes, aligned64Bytes
  ) where


#if MIN_VERSION_base(4,7,0)
import           Data.Proxy
#endif

import           GHC.TypeLits
import           Foreign.Ptr                 ( castPtr      )
import           Foreign.Storable            ( Storable(..) )
import           Prelude hiding              ( length       )


-- | A type @w@ forced to be aligned to the alignment boundary @alg@
newtype Aligned (alg :: Nat) w = Aligned { unAligned :: w }

-- | Align the value to 16-byte boundary
aligned16Bytes :: w -> Aligned 16 w
{-# INLINE aligned16Bytes #-}

-- | Align the value to 32-byte boundary
aligned32Bytes :: w -> Aligned 32 w
{-# INLINE aligned32Bytes #-}

-- | Align the value to 64-byte boundary
aligned64Bytes :: w -> Aligned 64 w
{-# INLINE aligned64Bytes #-}

aligned16Bytes = Aligned
aligned32Bytes = Aligned
aligned64Bytes = Aligned

#if MIN_VERSION_base(4,7,0)

-- | The constraint on the alignment o(since base 4.7.0).
type AlignBoundary (alg :: Nat) = KnownNat alg

alignmentBoundary :: AlignBoundary alg => Aligned alg a -> Int
alignmentBoundary = aB Proxy
  where aB :: AlignBoundary algn => Proxy algn -> Aligned algn a -> Int
        aB algn _ = fromEnum $ natVal algn

#else

-- | The constraint on the alignment (pre base 4.7.0).
type AlignBoundary (alg :: Nat) = SingI alg

alignmentBoundary :: AlignBoundary algn => Aligned algn a -> Int
alignmentBoundary = withSing aB
  where aB        ::  AlignBoundary algn => Sing algn      -> Aligned algn a -> Int
        aB algn _ = fromEnum $ fromSing algn


#endif


instance (Storable a, AlignBoundary alg) => Storable (Aligned alg a) where

  sizeOf = sizeOf . unAligned

  alignment alg = lcm valueAlignment forceAlignment
    where valueAlignment = alignment $ unAligned alg
          forceAlignment = alignmentBoundary alg

  peek = fmap Aligned .  peek . castPtr

  poke ptr = poke (castPtr ptr) . unAligned
