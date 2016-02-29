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

-- | Function that returns the dimension of the tuple. The dimension
-- is calculated without inspecting the tuple and hence the term
-- @`dimension` (undefined :: Tuple 5 Int)@ will evaluate to 5.
dimension :: (V.Unbox a, SingI dim) => Tuple dim a -> Int
dimension = withSing dimensionP
  where dimensionP :: (SingI dim, V.Unbox a)
                   => Sing dim
                   -> Tuple dim a
                   -> Int
        dimensionP sz _ = fromEnum $ fromSing sz

-- | Function to make the type checker happy
getA :: Tuple dim a -> a
getA _ = undefined

-- | Get the dimension to parser
getParseDimension :: (V.Unbox a, SingI dim) => Parser (Tuple dim a) -> Int
getParseDimension = dimension . getTupFromP
  where getTupFromP   :: (V.Unbox a, SingI dim) =>
                         Parser (Tuple dim a) -> Tuple dim a
        getTupFromP _ = undefined



instance (V.Unbox a, Storable a, SingI dim) => Storable (Tuple dim a) where
  sizeOf tup = dimension tup * sizeOf (getA tup)
  alignment  = alignment . getA

  peek  = unsafeRunParser tupParser . castPtr
    where len = getParseDimension tupParser
          tupParser = Tuple <$> unsafeParseStorableVector len

  poke ptr tup = unsafeWrite writeTup cptr
    where writeTup = writeStorableVector $ unTuple tup
          cptr     = castPtr ptr

instance (V.Unbox a, EndianStore a, SingI dim)
         => EndianStore (Tuple dim a) where
  load = unsafeRunParser $ tupParser
    where tupParser = Tuple <$> unsafeParseVector len
          len       = getParseDimension tupParser

  store cptr tup = unsafeWrite writeTup cptr
    where writeTup = writeVector $ unTuple tup


instance (V.Unbox a, Equality a) => Equality (Tuple dim a) where
  eq (Tuple u) (Tuple v) = V.foldl' mappend mempty $ V.zipWith eq u v

-- | Equality checking is timing safe.
instance (V.Unbox a, Equality a) => Eq (Tuple dim a) where
  (==) = (===)

-- | Construct a tuple out of the list. This function is unsafe and
-- will result in run time error if the list is not of the correct
-- dimension.

unsafeFromList :: (V.Unbox a, SingI dim) => [a] -> Tuple dim a
unsafeFromList xs
  | dimension tup == L.length xs = tup
  | otherwise                    = wrongLengthMesg
  where tup = Tuple $ V.fromList xs
        wrongLengthMesg = error "tuple: unsafeFromList: wrong length"

-- | Computes the initial fragment of a tuple. No length needs to be given
-- as it is infered from the types.
initial :: (V.Unbox a, SingI dim0, SingI dim1)
         => Tuple dim1 a
         -> Tuple dim0 a
initial tup = tup0
  where tup0 = Tuple $ V.take (dimension tup0) $ unTuple tup
