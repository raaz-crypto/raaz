{-# LANGUAGE CPP #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleContexts      #-}

-- | This module defines combinators, types and instances for defining
-- timing safe equality checks.
module Raaz.Core.Types.Equality
       ( -- * Timing safe equality checking.
         -- $timingSafeEquality$
         Equality(..), (===)
       -- ** The result of comparion.
       , Result
       ) where

import           Control.Monad               ( liftM )
import           Data.Bits

#if !MIN_VERSION_base(4,8,0)
import Data.Monoid  -- Import only when base < 4.8.0
#endif

import qualified Data.Vector.Generic         as G
import qualified Data.Vector.Generic.Mutable as GM
import           Data.Vector.Unboxed         ( MVector(..), Vector, Unbox )
import           Data.Word



-- $timingSafeEquality$
--
-- Cryptographic secrets should be compared using a constant time
-- equality function, i.e. the success or failure of comparing two
-- values @u@ and @v@ should /not/ depend on the actual values of @u@
-- and @v@. All cryptographically sensitive data exposed by this
-- library are instances of the class `Equality` which plays the role
-- analogues to `Eq`. The `eq` function which a member of the
-- `Equality` class returns the result of the comparison as the type
-- `Result` and not `Bool` so as to avoid timing attacks due to
-- short-circuting of the AND-operation.
--
-- The `Result` type is an opaque type to avoid the user from
-- compromising the equality comparisons by pattern matching on it. To
-- combine the results of two comparisons one can use the monoid
-- instance of `Result`, i.e. if @r1@ and @r2@ are the results of two
-- comparisons then @r1 `mappend` r2@ essentially takes the AND of
-- these results but this and is not short-circuited and is timing
-- independent.
--
-- Instance for basic word types are provided by the library and users
-- are expected to build the `Equality` instances of compound types by
-- combine the results of comparisons using the monoid instance of
-- `Result`. Once an instance for `Equality` is defined for a
-- cryptographically sensitive data type, we define the `Eq` for it
-- indirectly using the `Equality` instance and the operation `===`.
--
-- Ensure that you define the `Equality` instance first and then get
-- an `Eq` instance out of it. Also be careful when using the @deriving@
-- clause. For example the following deriving clause is safe.
--
-- > newtype Foo = Foo Bar deriving (Equality, Eq)
--
-- The deriving clause given below
--
-- > newtype Foo = Foo Bar deriving Eq
--
-- is also safe for @Foo@ if it is safe for @Bar@. However, not having
-- an instance of `Equality` for Foo makes it difficult for defining
-- timing safe equality for say a type like @(Foo, Foo)@.
--
-- The following definition is bad and the equality of Foo is not
-- constant time even if that of Bar and Biz are.
--
-- > data Foo = Foo Bar Biz deriving Eq


-- > -- instead do the
-- > instance Equality Foo where

-- | The result of a comparison. This is an opaque type and the monoid instance essentially takes
-- AND of two comparisons in a timing safe way.
newtype Result =  Result { unResult :: Word }

-- | Checks whether a given equality comparison is successful.
isSuccessful :: Result -> Bool
{-# INLINE isSuccessful #-}
isSuccessful = (==0) . unResult

instance Monoid Result where
  mempty      = Result 0
  mappend a b = Result (unResult a .|. unResult b)
  {-# INLINE mempty  #-}
  {-# INLINE mappend #-}

-- | MVector for Results.
newtype instance MVector s Result = MV_Result (MVector s Word)
-- | Vector of Results.
newtype instance Vector    Result = V_Result  (Vector Word)

instance Unbox Result

instance GM.MVector MVector Result where
  {-# INLINE basicLength #-}
  {-# INLINE basicUnsafeSlice #-}
  {-# INLINE basicOverlaps #-}
  {-# INLINE basicUnsafeNew #-}
  {-# INLINE basicUnsafeReplicate #-}
  {-# INLINE basicUnsafeRead #-}
  {-# INLINE basicUnsafeWrite #-}
  {-# INLINE basicClear #-}
  {-# INLINE basicSet #-}
  {-# INLINE basicUnsafeCopy #-}
  {-# INLINE basicUnsafeGrow #-}
  basicLength          (MV_Result v)            = GM.basicLength v
  basicUnsafeSlice i n (MV_Result v)            = MV_Result $ GM.basicUnsafeSlice i n v
  basicOverlaps (MV_Result v1) (MV_Result v2)   = GM.basicOverlaps v1 v2

  basicUnsafeRead  (MV_Result v) i              = Result `liftM` GM.basicUnsafeRead v i
  basicUnsafeWrite (MV_Result v) i (Result x)   = GM.basicUnsafeWrite v i x

  basicClear (MV_Result v)                      = GM.basicClear v
  basicSet   (MV_Result v)         (Result x)   = GM.basicSet v x

  basicUnsafeNew n                              = MV_Result `liftM` GM.basicUnsafeNew n
  basicUnsafeReplicate n     (Result x)         = MV_Result `liftM` GM.basicUnsafeReplicate n x
  basicUnsafeCopy (MV_Result v1) (MV_Result v2) = GM.basicUnsafeCopy v1 v2
  basicUnsafeGrow (MV_Result v)   n             = MV_Result `liftM` GM.basicUnsafeGrow v n

#if MIN_VERSION_vector(0,11,0)
  basicInitialize (MV_Result v)               = GM.basicInitialize v
#endif



instance G.Vector Vector Result where
  {-# INLINE basicUnsafeFreeze #-}
  {-# INLINE basicUnsafeThaw #-}
  {-# INLINE basicLength #-}
  {-# INLINE basicUnsafeSlice #-}
  {-# INLINE basicUnsafeIndexM #-}
  {-# INLINE elemseq #-}
  basicUnsafeFreeze (MV_Result v)             = V_Result  `liftM` G.basicUnsafeFreeze v
  basicUnsafeThaw (V_Result v)                = MV_Result `liftM` G.basicUnsafeThaw v
  basicLength (V_Result v)                    = G.basicLength v
  basicUnsafeSlice i n (V_Result v)           = V_Result $ G.basicUnsafeSlice i n v
  basicUnsafeIndexM (V_Result v) i            = Result   `liftM`  G.basicUnsafeIndexM v i

  basicUnsafeCopy (MV_Result mv) (V_Result v) = G.basicUnsafeCopy mv v
  elemseq _ (Result x)                        = G.elemseq (undefined :: Vector a) x



-- | In a cryptographic setting, naive equality checking is
-- dangerous. This class is the timing safe way of doing equality
-- checking. The recommended method of defining equality checking for
-- cryptographically sensitive data is as follows.
--
-- 1. Define an instance of `Equality`.
--
-- 2. Make use of the above instance to define `Eq` instance as follows.
--
-- > data SomeSensitiveType = ...
-- >
-- > instance Equality SomeSensitiveType where
-- >          eq a b = ...
-- >
-- > instance Eq SomeSensitiveType where
-- >      (==) a b = a === b
--
class Equality a where
  eq :: a -> a -> Result

-- | Check whether two values are equal using the timing safe `eq`
-- function. Use this function when defining the `Eq` instance for a
-- Sensitive data type.
(===) :: Equality a => a -> a -> Bool
(===) a b = isSuccessful $ eq a b

instance Equality Word where
  eq a b = Result $ a `xor` b

instance Equality Word8 where
  eq w1 w2 = Result $ fromIntegral $ xor w1 w2

instance Equality Word16 where
  eq w1 w2 = Result $ fromIntegral $ xor w1 w2

instance Equality Word32 where
  eq w1 w2 = Result $ fromIntegral $ xor w1 w2


#include "MachDeps.h"
instance Equality Word64 where
-- It assumes that Word size is atleast 32 Bits
#if WORD_SIZE_IN_BITS < 64
  eq w1 w2 = eq w11 w21 `mappend` eq w12 w22
    where
      w11 :: Word
      w12 :: Word
      w21 :: Word
      w22 :: Word
      w11 = fromIntegral $ w1 `shiftR` 32
      w12 = fromIntegral w1
      w21 = fromIntegral $ w2 `shiftR` 32
      w22 = fromIntegral w2
#else
  eq w1 w2 = Result $ fromIntegral $ xor w1 w2
#endif

-- Now comes the boring instances for tuples.

instance ( Equality a
         , Equality b
         ) => Equality (a , b) where
  eq (a1,a2) (b1,b2) = eq a1 b1 `mappend` eq a2 b2


instance ( Equality a
         , Equality b
         , Equality c
         ) => Equality (a , b, c) where
  eq (a1,a2,a3) (b1,b2,b3) = eq a1 b1 `mappend`
                             eq a2 b2 `mappend`
                             eq a3 b3


instance ( Equality a
         , Equality b
         , Equality c
         , Equality d
         ) => Equality (a , b, c, d) where
  eq (a1,a2,a3,a4) (b1,b2,b3,b4) = eq a1 b1 `mappend`
                                   eq a2 b2 `mappend`
                                   eq a3 b3 `mappend`
                                   eq a4 b4

instance ( Equality a
         , Equality b
         , Equality c
         , Equality d
         , Equality e
         ) => Equality (a , b, c, d, e) where
  eq (a1,a2,a3,a4,a5) (b1,b2,b3,b4,b5) = eq a1 b1 `mappend`
                                         eq a2 b2 `mappend`
                                         eq a3 b3 `mappend`
                                         eq a4 b4 `mappend`
                                         eq a5 b5


instance ( Equality a
         , Equality b
         , Equality c
         , Equality d
         , Equality e
         , Equality f
         ) => Equality (a , b, c, d, e, f) where
  eq (a1,a2,a3,a4,a5,a6) (b1,b2,b3,b4,b5,b6) = eq a1 b1 `mappend`
                                               eq a2 b2 `mappend`
                                               eq a3 b3 `mappend`
                                               eq a4 b4 `mappend`
                                               eq a5 b5 `mappend`
                                               eq a6 b6

instance ( Equality a
         , Equality b
         , Equality c
         , Equality d
         , Equality e
         , Equality f
         , Equality g
         ) => Equality (a , b, c, d, e, f, g) where
  eq (a1,a2,a3,a4,a5,a6,a7) (b1,b2,b3,b4,b5,b6,b7) = eq a1 b1 `mappend`
                                                     eq a2 b2 `mappend`
                                                     eq a3 b3 `mappend`
                                                     eq a4 b4 `mappend`
                                                     eq a5 b5 `mappend`
                                                     eq a6 b6 `mappend`
                                                     eq a7 b7
