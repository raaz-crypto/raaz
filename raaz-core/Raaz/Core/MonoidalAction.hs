{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE Arrows                     #-}

-- | A module that abstracts out monoidal actions.
module Raaz.Core.MonoidalAction
       ( -- * Basics
         -- $basics$
         LAction (..), Distributive, SemiR (..), (<++>)
         -- ** Monoidal action on functors
       , LActionF(..), DistributiveF, TwistRF (..), unTwistRF
         -- * Fields
         -- $fields$
       , FieldA, FieldM, Field, computeField, runFieldM, liftToFieldM
       ) where

import Control.Arrow
import Control.Applicative
import Data.Monoid

import Raaz.Core.Types    (CryptoPtr, LengthUnit)
import Raaz.Core.Util.Ptr (movePtr)

------------------ Actions and Monoidal actions -----------------------

-- $basics$
--
-- Consider any instance @l@ of a length unit as a monoid under
-- addition. Length units acts on pointers by displacing them. It
-- turns out that this action is crucial in abstracting out many
-- pointer manipulations in our library. In particular, Applicative
-- parsers, memory allocators and data serialisers can be abstractly
-- captured using this action.
--
-- We start with setting up some terminology.  Our setting here is a
-- space of points (captured by the type @space@) on which a monoid
-- (captured by the type @m@) acts. The space which we are most
-- interested in is the space of `CryptoPtr` and the monoid that act
-- on it can be any instance of `LengthUnit` as described above.
--
-- In this module, we consider /left/ actions of monoids, although
-- right actions can be analogously defined as well. For applications
-- we have in mind, namely for parsers etc, it is sufficient to
-- restrict our attention to left actions.  The following convention
-- is used when dealing with monoidal actions. Right actions are
-- written using the exponential notation and left actions in
-- multiplicative notation. The advantage of this differing convention
-- is that the laws of monoid action takes a form that is familiar to
-- us.
--
-- When monoids acting on monoidal spaces, i.e. the space itself is
-- monoid, we make the following conventions: For right actions both
-- monoidal operations are written multiplicatively. This is because,
-- we can use the familiar laws of exponentiation for talking about
-- stuff. For left actions, we think of the space as an additive
-- monoid. Again the usual laws of scalar multiplication is valid
-- here.

-- | A monoid @g@ acting on the left of a space. Think of a left
-- action as a multiplication with the monoid. It should satisfy the
-- law:
--
-- > 1 <.> p = p                         -- identity
-- > (a <> b) <.> p  = a <.> (b <.> p)   -- successive displacements
--
class Monoid m => LAction m space where
  (<.>) :: m -> space -> space

infixr 6 <.>

-- | An alternate symbol for <> more useful in the additive context.
(<++>) :: Monoid m => m -> m -> m
(<++>) = (<>)
{-# INLINE (<++>) #-}

infixr 5 <++>

-- | The most interesting monoidal action for us.
instance LengthUnit u => LAction (Sum u) CryptoPtr where
  a <.> ptr  = movePtr ptr (getSum a)


-- | Uniform action of a monoid on a functor. The laws that should
-- be satisfied are:
--
--
-- > 1 <<.>> fx  = fx
-- > (a <> b) <<.>> fx  = a . (b <<.>> fx)
-- > m <<.>> fmap f u = fmap f (m <<.>> u)   -- acts uniformly
--
class (Monoid m, Functor f) => LActionF m f where
  (<<.>>) :: m -> f a -> f a


---------------------- The semi-direct products ------------------------

-- | A left-monoid action on a monoidal-space, i.e. the space on which
-- the monoid acts is itself a monoid, is /distributive/ if it
-- satisfies the law:
--
-- > a <.> (p <> q)  = (a <.> p) <> (a <.> q).
--
-- The above law implies that every element @m@ is a monoid
-- homomorphism.
class (LAction m space, Monoid space) => Distributive m space

-- | The semidirect product Space ⋊ Monoid. For monoids acting on
-- monoidal spaces distributively the semi-direct product is itself a
-- monoid. It turns out that data serialisers can essentially seen as
-- a semidirect product.
newtype SemiR space m = SemiR { unSemiR :: (space, m) }

instance Distributive m space => Monoid (SemiR space m) where
  mempty = SemiR (mempty, mempty)
  mappend (SemiR (x, a)) (SemiR (y, b)) = SemiR (x <++>  a <.> y,  a <> b)

--------------------------- Twisted functors ----------------------------



-- | The generalisation of distributivity to applicative
-- functors. This generalisation is what allows us to capture
-- applicative functors like parsers. For an applicative functor, and
-- a monoid acting uniformly on it, we say that the action is
-- distributive if the following laws are satisfied:
--
-- > m <<.>> (pure a) = pure a            -- pure values are stoic
-- > m <<.>> (a <*> b) = (m <<.>> a) <*> (m <<.>> b)  -- dist
class (Applicative f, LActionF m f) => DistributiveF m f

-- | The twisted functor is essentially a generalisation of
-- semi-direct product to applicative functors.
newtype TwistRF f m a = TwistRF { unTwistRF :: (f a, m) }


instance Functor f => Functor (TwistRF f m) where
  fmap f (TwistRF (x, m)) = TwistRF (fmap f x, m)

-- Proof of functor laws.
--
-- fmap id (TwistRF (x, m)) = TwistRF (fmap id x, m)
--                          = TwistRF (x, m)
--
-- fmap (f . g)  (TwistRF fx m) = TwistRF (fmap (f . g) x, m)
--                              = TwistRF (fmap f . fmap g $ x, m)
--                              = TwistRF (fmap f (fmap g x), m)
--                              = fmap f   $ TwistRF (fmap g x,  m)
--                              = (fmap f . fmap g) (TwistRF fx) m)
--

instance DistributiveF m f => Applicative (TwistRF f m) where
  pure a = TwistRF (pure a, mempty)

  TwistRF (f,mf)  <*> TwistRF (val, mval)  = TwistRF (res, mres)
    where res  = f <*> (mf <<.>> val)
          mres = mf <> mval

-- Consider an expression @u = u1 <*> u2 <*> ... <ur>@ where
-- ui = TwistRF fi mi
--
-- u = TwistRF f m where m = m1 <> m2 <> .. <> mr
-- f = f1 <*> m1 f2 <*> (m1 m2) f3 ...    <*> (m1 m2 .. mr-1) fr.
--
-- We will separately verify the functor part and the monoid
-- part of the  ofNow we can verify the laws of applicative
--
--


------------------------- A generic field -----------------------------------

-- $fields$
--
-- The main goal behind looking at monoidal actions are to captures
-- concrete objects of interest to us like parsers, serialisers and
-- memory allocators. These are essentially functions with domain
-- `CryptoPtr`. For example, a parser is a function that takes a
-- `CryptoPtr`, reads @n@ bytes say and produces a result a. To
-- sequence the next parse we need to essentially keep track of this
-- @n@. If we abstract this out to the general setting we need to
-- consider functions whose domain is the space of points. We use the
-- physicist's terminology and call them fields. The action of the
-- monoid on a space of points naturally extends to fields on them
--
-- @F^g   = λ x -> F (x^g) @
--
-- For our applications, we need to define generalised fields
-- associated with arrows. This is because we often have to deal with
-- functions that have side effects (i.e. `Kleisli` arrows). However,
-- for conceptual understanding, it is sufficient to stick to ordinary
-- functions. In fact, the informal proofs that we have scattered in
-- the source all have been written only for the arrow @->@.

-- | A field on the space is a function from the points in the space
-- to some value. Here we define it for a general arrow.

type FieldA arrow = WrappedArrow arrow


-- | A field where the underlying arrow is the (->). This is normally
-- what we call a field.
type Field = FieldA (->)

-- | Compute the value of a field at a given point in the space.
computeField :: Field space b -> space -> b
computeField = unwrapArrow

-- | A monadic arrow field.
type FieldM monad = FieldA (Kleisli monad)

-- | Lift a monadic action to FieldM.
liftToFieldM :: Monad m => (a -> m b) -> FieldM m a b
liftToFieldM = WrapArrow . Kleisli

-- | Runs a monadic field at a given point in the space.
runFieldM :: FieldM monad space b -> space -> monad b
runFieldM = runKleisli . unwrapArrow

-- | The action on the space translates to the action on field.
instance (Arrow arrow, LAction m space) => LActionF m (WrappedArrow arrow space) where
  m <<.>> field =   WrapArrow $ unwrapArrow field <<^ (m<.>)
