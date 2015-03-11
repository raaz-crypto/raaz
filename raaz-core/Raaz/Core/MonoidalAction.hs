{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE Arrows                     #-}

-- | A module that abstracts out monoidal actions.
module Raaz.Core.MonoidalAction
       ( -- * Basics
         -- $basics$
         RAction(..), LAction(..)
       , Monoidal, Distributive, (<++>)
         -- * Fields
       , FieldA, FieldM, Field, computeField, runFieldM, liftToFieldM
       , SemiR(..), SemiL(..)
       , TwistRA(..), TwistR, TwistRM
       ) where

import Control.Arrow
import Control.Applicative
import Control.Category (Category)
import Data.Monoid

import Raaz.Core.Types    (CryptoPtr, LengthUnit)
import Raaz.Core.Util.Ptr (movePtr)

------------------ Actions and Monoidal actions -----------------------

-- $basics$
--
-- Our setting here is a space of points (captured by the type
-- @points@) on which a monoid (captured by the type @g@) acts. The
-- space which we are most interested in is the space of
-- `CryptoPtr`. Any `LengthUnit` with addition being its monoidal
-- operation acts on it via the `movePtr`.
--
-- We will consider both right and left actions of monoids. This
-- module captures /monoidal actions/ on spaces and some abstractions
-- related to that.  A lot of pointer gymnastics that are involved in
-- this library like serialisation, parsing and memory allocations can
-- be captured using the abstractions here.
--
-- The following convention is used when dealing with monoidal
-- actions.  Right actions are written using the exponential notation
-- and left actions in multiplicative notation. When monoids acting on
-- monoidal spaces, i.e. the space itself is monoid, we make the
-- following conventions: For right actions both monoidal operations
-- are written multiplicatively. This is because, we can use the
-- familiar laws of exponentiation for talking about stuff. For left
-- actions, we think of the space as an additive monoid. Again the
-- usual laws of scalar multiplication is valid here.


-- | A (multiplicative) monoid @g@ acting on the right of a space. For
-- right actions it is intuitive to think of it as an exponentiation
-- and the monoid action as a multiplication. The following laws
-- should be true for any right action:
--
-- [/identity law:/]
--            @p ^ 1 = p@
-- [/successive displacements:/]
--           @p ^ (a . b) = (p ^ a) ^ b@
class Monoid g => RAction point g where
  -- | Apply the monoid on the point
  (<^>)   ::  point -> g -> point


-- | A monoid action on a monoidal space is called Monoidal if it
-- satisfies the additional law:
--
-- @(p1 . p2) ^ g = (p1 ^ g) . (p2 ^ g)@.
--
-- It means that for every element @g@ is monoid morphism of the
-- space.
class (RAction point g, Monoid point) => Monoidal point g

infixl 7 <^>

-- | A monoid @g@ acting on the left of a space. Think of a left
-- action as a multiplication with the monoid. It should satisfy the
-- law:
--
-- [/identity law:/]
--            @1 . p = p@
-- [/successive displacements:/]
--           @ (a . b)  p  = a . (b . p)@
class Monoid g => LAction g point where
  (<.>) :: g -> point -> point

infixr 6 <.>

-- | An alternate symbol for <> more useful in the additive context.
(<++>) :: Monoid m => m -> m -> m
(<++>) = (<>)
{-# INLINE (<++>) #-}

infixr 5 <++>

-- | A left-monoid action on a monoidal-space, i.e. the points of the
-- space itself is a monoid is called Distributive if it satisfies the
-- law:
--
-- @ a . (p + q)  = a . p + a  q@.
--
-- Recall our convention here is to use @+@ for the monoid operation
-- of the space.  It means that for every element @g@ is morphism.
class (LAction g point, Monoid point) => Distributive g point

-- | The most interesting monoidal action for us.
instance LengthUnit u => RAction CryptoPtr (Sum u) where
  ptr <^> a  = movePtr ptr (getSum a)

instance LengthUnit u => LAction (Sum u) CryptoPtr where
  a <.> ptr  = movePtr ptr (getSum a)

------------------------- A generic field -----------------------------------

-- | A field on the space is a function from the points in the space
-- to some value. Here we define it for a general arrow.
newtype FieldA arrow point value =
  FieldA { unFieldA :: (arrow point value) } deriving (Category, Arrow)

-- | A field where the underlying arrow is the (->). This is normally
-- what we call a field.
type Field = FieldA (->)

-- | Compute the value of a field at a given point
computeField :: Field point b -> point -> b
computeField = unFieldA

-- | A monadic arrow field.
type FieldM m = FieldA (Kleisli m)

-- | Lift a monadic action to FieldM.
liftToFieldM :: Monad m => (a -> m b) -> FieldM m a b
liftToFieldM action = FieldA (Kleisli action)

-- | Runs a monadic field at a given point.
runFieldM :: FieldM m a b -> a -> m b
runFieldM = runKleisli . unFieldA

instance Arrow a => Functor (FieldA a point) where
  fmap f fM = fM >>^ f

-- A proof that this is indeed applicative is available in Functional
-- pearl "Applicative programming with effects" Conor McBride and Ross
-- Patterson.
instance Arrow a => Applicative (FieldA a point) where
  pure v = arr (const v)
  (<*>) f x = proc p -> do func <- f -< p
                           val  <- x -< p
                           returnA   -< func val

-- | A monoidal field is a monoid in itself @f <> g = \ point -> f
-- point <> g point@
instance (Arrow arrow, Monoid value) => Monoid (FieldA arrow point value) where
  mempty        =  arr $ const mempty
  mappend f1 f2 =  proc p -> do n1 <- f1 -< p
                                n2 <- f2 -< p
                                returnA -< n1 <> n2


-- | Exponentiation carry over to monoidal fields. @f^a (x) = f
-- (x^a)@.
instance (Arrow arrow, RAction point g) => RAction (FieldA arrow point value) g where
  f <^> a  = f <<^ (<^>a) -- first exponentiate the argument and apply
                          -- the function.

-- | So does left action @(a . f) (x) = f(a . x)@.
instance (Arrow arrow, LAction g point) => LAction g (FieldA arrow point value) where
  a <.> f = f <<^ (a<.>) -- first displace the argument and apply the
                         -- function.

-- | Exponentiation on monoidal fields are monoidal. Proof: @ (fg)^a (x) = (fg)(x^a) =
-- f (x^a) . g(x^a) = (f^a . g^a) (x)@
instance (Arrow arrow, Monoid value, RAction point g) => Monoidal (FieldA arrow point value) g

-- | On monoidal fields the left action is distributive. Proof: @(a
-- . (f <++> g)) = f (a . x) <++> g (a . x) = (f^a . g^a) (x)@
instance (Arrow arrow, Monoid value, LAction g point) => Distributive g (FieldA arrow point value)




---------------------- The semi-direct products ------------------------

-- | The semidirect product Space ⋊ Monoid.
newtype SemiR point g = SemiR { unSemiR :: (point, g) }

-- | The semidirect product Monoid ⋉ Space.
newtype SemiL g point = SemiL { unSemiL :: (g, point) }

instance Distributive g point => Monoid (SemiR point g) where
  mempty = SemiR (mempty, mempty)
  mappend (SemiR (x, a)) (SemiR (y, b)) = SemiR (x <++>  a <.> y,  a <> b)

instance Monoidal  point g => Monoid (SemiL g point) where
  mempty = SemiL (mempty, mempty)
  mappend (SemiL (a, x)) (SemiL (b, y)) = SemiL (a <> b, x <^> b  <> y)

-- | The twisted field. This is essentially a field on the space of
-- points tagged with an extra displacement by the monoid. The
-- applicative instance also keeps track of the extra displacement and
-- acts accordingly. This is the applicative generalisation of the
-- semidirect product `SemiR`.
data TwistRA a point g value = TwistRA { twistFieldA        :: FieldA a point value
                                       , twistDisplacement  :: g
                                       }

instance Arrow arrow => Functor (TwistRA arrow point g)  where
  fmap f (TwistRA fld g) = TwistRA (fmap f fld) g

instance (Monoid g, Arrow arrow, LAction g point) => Applicative (TwistRA arrow point g) where
  pure x  = TwistRA (pure x) mempty
  TwistRA f u <*> TwistRA val v = TwistRA (f <*> (u <.> val)) (u <> v)

-- | Twisted field when the underlying arrow is @(->)@.
type TwistR point g = TwistRA (->) point g

-- | Monadic twisted field.
type TwistRM m point g = TwistRA (Kleisli m) point g
