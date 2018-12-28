{-# LANGUAGE CPP                   #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE ConstraintKinds      #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE RankNTypes            #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeOperators         #-}

-- | Tuples of unboxed values with type level length encoding.
module Raaz.Core.Types.Tuple
       ( -- * Length encoded tuples
         Tuple, Dimension, dimension, dimension', initial, diagonal
       , repeatM, zipWith, map
         -- ** Unsafe operations
       , unsafeFromList, unsafeToVector
       ) where

import           Control.Applicative
import qualified Data.List           as L
import           Data.Monoid
import           Data.Proxy
import qualified Data.Vector.Unboxed as V
import           GHC.TypeLits
import           Foreign.Ptr                 ( castPtr, Ptr )
import           Foreign.Storable            ( Storable(..) )
import           Prelude hiding              ( length, zipWith, map )


import Raaz.Core.Types.Equality
import Raaz.Core.Types.Endian
import Raaz.Core.Transfer
import Raaz.Core.Parse.Applicative

-- | Tuples that encode their length in their types. For tuples, we call
-- the length its dimension.
newtype Tuple (dim :: Nat) a = Tuple { unTuple :: V.Vector a }
                             deriving Show

-- | Map function for tuples.
map :: (V.Unbox a, V.Unbox b) => (a -> b) -> Tuple dim a -> Tuple dim b
map f = Tuple . V.map f . unTuple

-- | Convert the tuple to vector.
unsafeToVector :: Tuple dim a -> V.Vector a
unsafeToVector = unTuple

instance (V.Unbox a, Equality a) => Equality (Tuple dim a) where
  eq (Tuple u) (Tuple v) = V.foldl' mappend mempty $ V.zipWith eq u v

-- | Equality checking is timing safe.
instance (V.Unbox a, Equality a) => Eq (Tuple dim a) where
  (==) = (===)

-- | Function to make the type checker happy
getA :: Tuple dim a -> a
getA _ = undefined


-- | The constaint on the dimension of the tuple (since base 4.7.0)
type Dimension (dim :: Nat) = KnownNat dim

{-@ assume natValInt :: Dimension dim => proxy dim -> { v : Int | v == dim } @-}
natValInt :: Dimension dim => proxy dim -> Int
natValInt = fromEnum . natVal

-- | Function that returns the dimension of the tuple. The dimension
-- is calculated without inspecting the tuple and hence the term
-- @`dimension` (undefined :: Tuple 5 Int)@ will evaluate to 5.
{-@ dimension :: Dimension dim  => Raaz.Core.Types.Tuple.Tuple dim a -> {n: Int | n == dim } @-}
dimension  :: Dimension dim => Tuple dim a -> Int
dimensionP :: Dimension dim
           => Proxy dim
           -> Proxy (Tuple dim a)
           -> Int
dimensionP sz _ = natValInt sz
dimension = dimensionP Proxy . pure

-- | Function that returns the dimension from the proxy of the
-- tuple. This is useful when we only have a proxy of the tuple at
-- hand. This is clearly possible because the dimension calculation
-- works at the type level and does not require looking at the value
-- of the tuple.
dimension' :: Dimension dim => Proxy (Tuple dim a) -> Int
dimension' = dimensionP Proxy

-- | Get the dimension to parser
getParseDimension :: (V.Unbox a, Dimension dim)
                  => Parser (Tuple dim a) -> Int
getParseDimension = dimension' . getProxy
  where getProxy :: Parser (Tuple dim a) -> Proxy (Tuple dim a)
        getProxy = const Proxy


instance (V.Unbox a, Storable a, Dimension dim)
         => Storable (Tuple dim a) where

  sizeOf tup = dimension tup * sizeOf (getA tup)
  alignment  = alignment . getA

  peek  = unsafeRunParser tupParser . castPtr
    where len = getParseDimension tupParser
          tupParser = Tuple <$> unsafeParseStorableVector len

  poke ptr tup = unsafeTransfer writeTup cptr
    where writeTup = writeStorableVector $ unTuple tup
          cptr     = castPtr ptr


instance (V.Unbox a, EndianStore a, Dimension dim)
         => EndianStore (Tuple dim a) where

  load = unsafeRunParser tupParser . castPtr
     where tupParser = Tuple <$> unsafeParseVector len
           len       = getParseDimension tupParser

  store ptr tup = unsafeTransfer writeTup cptr
     where writeTup = writeVector $ unTuple tup
           cptr     = castPtr ptr

  adjustEndian ptr n = adjustEndian (unTupPtr ptr) $ nos ptr Proxy
       where nos     :: Ptr (Tuple dim a) -> Proxy (Tuple dim a) -> Int
             nos _ w = dimension' w * n
             unTupPtr   :: Ptr (Tuple dim a) -> Ptr a
             unTupPtr   = castPtr


-- | Construct a tuple by repeating a monadic action.
repeatM :: (Functor m, Monad m, V.Unbox a, Dimension dim) => m a -> m (Tuple dim a)
repeatM = mkTupM Proxy
  where mkTupM :: (Functor m, V.Unbox a, Monad m, Dimension dim) => Proxy (Tuple dim a) -> m a -> m (Tuple dim a)
        mkTupM uTupProxy action = Tuple <$> V.replicateM (dimension' uTupProxy) action


-- | Construct a tuple out of the list. This function is unsafe and
-- will result in run time error if the list is not of the correct
-- dimension.
{-@ unsafeFromList :: (V.Unbox a, Dimension dim)
                   => { xs:[a] | len xs = dim }
                   -> Raaz.Core.Types.Tuple.Tuple dim a

@-}
unsafeFromList :: (V.Unbox a, Dimension dim) => [a] -> Tuple dim a
unsafeFromList xs
  | dimension tup == L.length xs = tup
  | otherwise                    = wrongLengthMesg
  where tup = Tuple $ V.fromList xs
        wrongLengthMesg = error "tuple: unsafeFromList: wrong length"

-- | Computes the initial fragment of a tuple. No length needs to be given
-- as it is infered from the types.
{-@ lazy initial @-}
initial ::  (V.Unbox a, Dimension dim0)
         => Tuple dim1 a
         -> Tuple dim0 a
initial = mkTuple Proxy
  where mkTuple :: (V.Unbox a, Dimension dim0) => Proxy (Tuple dim0 a) -> Tuple dim1 a  -> Tuple dim0 a
        mkTuple uTupProxy tup = Tuple $ V.take (dimension' uTupProxy) $ unTuple tup

-- TODO: Put a constraint that dim0 <= dim1

-- | The @diagonal a@ gives a tuple, all of whose entries is @a@.
diagonal :: (V.Unbox a, Dimension dim) => a -> Tuple dim a
diagonal = mkTup Proxy
  where mkTup :: (V.Unbox a, Dimension dim) => Proxy (Tuple dim a) -> a -> Tuple dim a
        mkTup uTupProxy a = Tuple $ V.replicate (dimension' uTupProxy) a


-- | A zipwith function for tuples

zipWith :: (V.Unbox a, V.Unbox b, V.Unbox c)
        => (a -> b -> c)
        -> Tuple dim a
        -> Tuple dim b
        -> Tuple dim c
zipWith f (Tuple at) (Tuple bt)= Tuple $ V.zipWith f at bt
