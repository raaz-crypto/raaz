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
       , Result
       ) where

import qualified Data.Vector.Generic         as G
import qualified Data.Vector.Generic.Mutable as GM
import           Data.Vector.Unboxed         ( MVector(..), Vector, Unbox )
import           Raaz.Core.Prelude



-- $timingSafeEquality$
--
-- Many cryptographic setting require comparing two secrets and such
-- comparisons should be timing safe, i.e. the time taken to make the
-- comparison should not depend on the actual values that are
-- compared. Unfortunately, the equality comparison of may Haskell
-- types like `ByteString`, provided via the class `Eq` is /not/
-- timing safe. In raaz we take special care in defining the `Eq`
-- instance of all cryptographically sensitive types which make them
-- timing safe . For example, if we compare two digests @dgst1 ==
-- dgst2@, the `Eq` instance is defined in such a way that the time
-- taken is constant irrespective of the actual values. We also give a
-- mechanism to build timing safe equality for more complicated types
-- that user might need to define in her use cases as we now describe.
--
-- The starting point of defining such timing safe equality is the
-- class `Equality` which plays the role `Eq`. The member function
-- `eq` playing the role of (`==`) with an important difference.  The
-- comparison function `eq` returns the type type `Result` instead of
-- `Bool` and it is timing safe. The `Eq` instance is then defined by
-- making use of the operator (`===`). Thus a user of the library can
-- stick to the familiar `Eq` class and get the benefits of timing
-- safe comparison
--
-- == Building timing safe equality for Custom types.
--
-- For basic types like `Word32`, `Word64` this module defines
-- instances of `Equality`. The `Tuple` type inherits the `Equality`
-- instance from its base type. As a developer, new crypto-primitives
-- or protocols often need to define timing safe equality for types
-- other than those exported here. This is done in two stages.
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
-- === Combining multiple comparisons using Monoid operations
--
-- The `Result` type is an opaque type and does not allow inspection
-- via a pattern match or conversion to `Bool`. However, while
-- defining the `Equality` instance, we often need to perform an AND
-- of multiple comparison (think of comparing a tuple). This is where
-- the monoid instance of `Result` is useful. If @r1@ and @r2@ are the
-- results of two comparisons then @r1 `mappend` r2@ essentially takes
-- the AND of these results. However, unlike in the case of AND-ing in
-- `Bool`, `mappend` on the `Result` type does not short-circuit.  In
-- fact, the whole point of using `Result` type instead of `Bool` is
-- to avoid this short circuiting.
--
-- To illustrate, we have the following code fragment
--
-- > data Foo = Foo Word32 Word64
-- >
-- > instance Equality Foo where
-- >    eq (Foo a b) (Foo c d) = eq a c `mapped` eq b d
-- >
-- > instance Eq Foo where
-- >    (=) = (===)
--
-- == Automatic deriving of `Equality` instances.
--
-- We often find ourselves wrapping existing types in new types
-- keeping in line with the philosophy of distinguishing sematically
-- distinct data with their types. It would be tedious to repeat the
-- above process for each such type. Often, we can get away by just
-- deriving these instances thereby saving a lot of boilerplate. For
-- example, consider a data type that needs to keep a 128-byte
-- secret. A simple deriving class would work in such cases.
--
-- >
-- > newtype Secret = Secret (Tuple 128 Word8) deriving (Equality, Eq)
-- >
--
-- The `Eq` instance here would be timing safe because it is
-- essentially the `Eq` instance of tuples. The deriving `Equality` is
-- not strictly required here. However, we suggest keeping it so that
-- on can define timing safe equality for other types that contain a
-- component of type `Secret`.
--
-- === Beware: deriving clause can be dangerous
--
-- The deriving clause that we defined above while convenient, hides a
-- danger when not used properly. For example, consider the following
-- definitions.
--
-- > data    Bad      = Bad Bar Biz deriving Eq
-- > newtype BadAgain = BadAgain (Bar, Biz) deriving (Eq, Equality)
-- >
--
-- The comparison for the elements of the type `Bad` would leak some
-- timing information /even/ when `Bar` and `Biz` are instances of
-- `Equality` and thus have timing safe equalities themselves. This is
-- because the automatic derivation of `Eq` instances in the above two
-- cases performs a component by component comparison and combines the
-- result using @`and`@. Due to boolean short circuiting, this
-- will lead to timing information being leaked.
--
-- For product types, we can safely derive the `Equality` instance and use
-- it to define the @Eq@ instance as follows
--
-- >
-- > newtype Okey2 = Okey (Foo, Bar) deriving Equality
-- >
-- > instance Eq Okey2 where
-- >    (=) = (===)
-- >
--
--



-- | All types that support timing safe equality are instances of this class.
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


-- | The result of a comparison. This is an opaque type and the monoid instance essentially takes
-- AND of two comparisons in a timing safe way.
newtype Result =  Result { unResult :: Word }

instance Semigroup Result where
  (<>) a b = Result (unResult a .|. unResult b)

instance Monoid Result where
  mempty  = Result 0
  mappend = (<>)
  {-# INLINE mempty  #-}
  {-# INLINE mappend #-}

-- | Checks whether a given equality comparison is successful.
isSuccessful :: Result -> Bool
{-# INLINE isSuccessful #-}
isSuccessful = (==0) . unResult

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
  basicInitialize (MV_Result v)               = GM.basicInitialize v



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
