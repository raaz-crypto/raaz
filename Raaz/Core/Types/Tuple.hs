{-# LANGUAGE CPP                   #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeOperators         #-}

module Raaz.Core.Types.Tuple
       ( -- * Length encoded tuples
         Tuple, dimension, initial
         -- ** Unsafe operations
       , unsafeFromList
       ) where

import           Control.Applicative
import qualified Data.List           as L
import           Data.Monoid

#if MIN_VERSION_base(4,7,0)
import           Data.Proxy
#endif

import qualified Data.Vector.Unboxed as V
import           GHC.TypeLits
import           Foreign.Ptr                 ( castPtr      )
import           Foreign.Storable            ( Storable(..) )
import           Prelude hiding              ( length       )


import Raaz.Core.Types.Equality
import Raaz.Core.Types.Endian
import Raaz.Core.Write
import Raaz.Core.Parse.Applicative

-- | Tuples that encode their length in their types. For tuples, we call
-- the length its dimension
newtype Tuple (dim :: Nat) a = Tuple { unTuple :: V.Vector a }
                             deriving Show

instance (V.Unbox a, Equality a) => Equality (Tuple dim a) where
  eq (Tuple u) (Tuple v) = V.foldl' mappend mempty $ V.zipWith eq u v

-- | Equality checking is timing safe.
instance (V.Unbox a, Equality a) => Eq (Tuple dim a) where
  (==) = (===)


-- | Function to make the type checker happy
getA :: Tuple dim a -> a
getA _ = undefined

-- | Function that returns the dimension of the tuple. The dimension
-- is calculated without inspecting the tuple and hence the term
-- @`dimension` (undefined :: Tuple 5 Int)@ will evaluate to 5.
#if !MIN_VERSION_base(4,7,0)
dimension  :: (V.Unbox a, SingI dim) => Tuple dim a -> Int
dimensionP :: (SingI dim, V.Unbox a)
           => Sing dim
           -> Tuple dim a
           -> Int
dimension       = withSing dimensionP
dimensionP sz _ = fromEnum $ fromSing sz
#else
dimension  :: (V.Unbox a, KnownNat dim) => Tuple dim a -> Int
dimensionP :: (KnownNat dim, V.Unbox a)
           => Proxy dim
           -> Tuple dim a
           -> Int
dimensionP sz _ = fromEnum $ natVal sz
dimension = dimensionP Proxy
#endif

-- | Get the dimension to parser
#if !MIN_VERSION_base(4,7,0)
getParseDimension :: (V.Unbox a, SingI dim)
                  => Parser (Tuple dim a) -> Int
getTupFromP       :: (V.Unbox a, SingI dim)
                  => Parser (Tuple dim a) -> Tuple dim a
#else
getParseDimension :: (V.Unbox a, KnownNat dim)
                  => Parser (Tuple dim a)
                  -> Int
getTupFromP   :: (V.Unbox a, KnownNat dim)
              => Parser (Tuple dim a)
              -> Tuple dim a
#endif

getParseDimension = dimension . getTupFromP
getTupFromP _     = undefined


#if !MIN_VERSION_base(4,7,0)
instance (V.Unbox a, Storable a, SingI dim)
         => Storable (Tuple dim a) where
#else
instance (V.Unbox a, Storable a, KnownNat dim)
         => Storable (Tuple dim a) where
#endif
  sizeOf tup = dimension tup * sizeOf (getA tup)
  alignment  = alignment . getA

  peek  = unsafeRunParser tupParser . castPtr
    where len = getParseDimension tupParser
          tupParser = Tuple <$> unsafeParseStorableVector len

  poke ptr tup = unsafeWrite writeTup cptr
    where writeTup = writeStorableVector $ unTuple tup
          cptr     = castPtr ptr
#if !MIN_VERSION_base(4,7,0)
instance (V.Unbox a, EndianStore a, SingI dim)
         => EndianStore (Tuple dim a) where
#else
instance (V.Unbox a, EndianStore a, KnownNat dim)
         => EndianStore (Tuple dim a) where
#endif
  load = unsafeRunParser $ tupParser
    where tupParser = Tuple <$> unsafeParseVector len
          len       = getParseDimension tupParser

  store cptr tup = unsafeWrite writeTup cptr
    where writeTup = writeVector $ unTuple tup

-- | Construct a tuple out of the list. This function is unsafe and
-- will result in run time error if the list is not of the correct
-- dimension.
#if !MIN_VERSION_base(4,7,0)
unsafeFromList :: (V.Unbox a, SingI dim) => [a] -> Tuple dim a
#else
unsafeFromList :: (V.Unbox a, KnownNat dim) => [a] -> Tuple dim a
#endif
unsafeFromList xs
  | dimension tup == L.length xs = tup
  | otherwise                    = wrongLengthMesg
  where tup = Tuple $ V.fromList xs
        wrongLengthMesg = error "tuple: unsafeFromList: wrong length"

-- | Computes the initial fragment of a tuple. No length needs to be given
-- as it is infered from the types.
#if !MIN_VERSION_base(4,7,0)
initial :: (V.Unbox a, SingI dim0, SingI dim1)
         => Tuple dim1 a
         -> Tuple dim0 a
#else
initial :: (V.Unbox a, KnownNat dim0, KnownNat dim1)
         => Tuple dim1 a
         -> Tuple dim0 a
#endif
initial tup = tup0
  where tup0 = Tuple $ V.take (dimension tup0) $ unTuple tup
