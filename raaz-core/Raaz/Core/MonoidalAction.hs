{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE Arrows                     #-}

-- | A module that abstracts out monoidal actions.
module Raaz.Core.MonoidalAction
       ( -- * Basics
         -- $basics$
        LAction(..), Distributive, (<++>)
         -- * Fields
         -- $fields$
       , FieldA, FieldM, Field, computeField, runFieldM, liftToFieldM
       , SemiR(..)
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
-- Consider any instance @l@ of a length unit as a monoid under
-- addition. Length units acts on pointers by displacing them. It
-- turns out that this action is crucial in abstracting out many
-- pointer manipulations in our library. In particular, Applicative
-- parsers, memory allocators and data serialisers can be abstractly
-- captured using this action.
--
-- We start with setting up some terminology.  Our setting here is a
-- space of points (captured by the type @points@) on which a monoid
-- (captured by the type @g@) acts. The space which we are most
-- interested in is the space of `CryptoPtr` and the monoid that act
-- on it can be any instance of `LengthUnit` as described above.
--
-- In this module, we consider /left/ actions of monoids, although
-- right actions can be analogously defined as well. For applications
-- we have in mind, namely for parsers etc, it is sufficient to
-- restrict our attention to left actions.  The following convention
-- is used when dealing with monoidal actions.  Right actions are
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
-- associated with arrows (See the type `FieldA`). This is because we
-- often have to deal with functions that have side effects
-- (i.e. `Kleisli` arrows). However, for conceptual understanding, it
-- is sufficient to stick to ordinary functions. In fact, the informal
-- proofs that we have scattered in the source all have been written
-- only for the arrow @->@.

-- | A monoid @g@ acting on the left of a space. Think of a left
-- action as a multiplication with the monoid. It should satisfy the
-- law:
--
-- [identity law:]
--            @1 . p = p@
--
-- [successive displacements:]
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
-- @ a . (p + q)  = a . p + a . q@.
--
-- Recall our convention here is to use @+@ for the monoid operation
-- of the space.  It means that for every element @g@ is morphism.
class (LAction g point, Monoid point) => Distributive g point

-- | The most interesting monoidal action for us.
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



-- | So does left action @(a . f) (x) = f(a . x)@.
instance (Arrow arrow, LAction g point) => LAction g (FieldA arrow point value) where
  a <.> f = f <<^ (a<.>) -- first displace the argument and apply the
                         -- function.

-- | On monoidal fields the left action is distributive. Proof: @(a
-- . (f <++> g)) = f (a . x) <++> g (a . x) = (f^a . g^a) (x)@
instance (Arrow arrow, Monoid value, LAction g point) => Distributive g (FieldA arrow point value)

---------------------- The semi-direct products ------------------------

-- | The semidirect product Space ⋊ Monoid. It turns out that data
-- serialisers (to a buffer) can essentially seen as a semidirect
-- product.
newtype SemiR point g = SemiR { unSemiR :: (point, g) }

instance Distributive g point => Monoid (SemiR point g) where
  mempty = SemiR (mempty, mempty)
  mappend (SemiR (x, a)) (SemiR (y, b)) = SemiR (x <++>  a <.> y,  a <> b)


-- | The twisted field. This is essentially a field on the space of
-- points tagged with an extra displacement by the monoid. The
-- applicative instance also keeps track of the extra displacement and
-- acts accordingly. This is the applicative generalisation of the
-- semidirect product `SemiR` and in our specific case turns out to
-- capture applicative parsers.
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


{----------------------------- Right action --------------------------------

-- | A (multiplicative) monoid @g@ acting on the right of a space. For
-- right actions it is intuitive to think of it as an exponentiation
-- and the monoid action as a multiplication. The following laws
-- should be true for any right action:
--
-- [@identity law:@]
--       @p ^ 1 = p@
--
-- [@successive displacements:@]
--       @p ^ (a . b) = (p ^ a) ^ b@
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

instance LengthUnit u => RAction CryptoPtr (Sum u) where
  ptr <^> a  = movePtr ptr (getSum a)

-- | The semidirect product Monoid ⋉ Space.
newtype SemiL g point = SemiL { unSemiL :: (g, point) }

instance Monoidal  point g => Monoid (SemiL g point) where
  mempty = SemiL (mempty, mempty)
  mappend (SemiL (a, x)) (SemiL (b, y)) = SemiL (a <> b, x <^> b  <> y)

-- | Exponentiation carry over to monoidal fields. @f^a (x) = f
-- (x^a)@.
instance (Arrow arrow, RAction point g) => RAction (FieldA arrow point value) g where
  f <^> a  = f <<^ (<^>a) -- first exponentiate the argument and apply
                          -- the function.

-- | Exponentiation on monoidal fields are monoidal. Proof: @ (fg)^a (x) = (fg)(x^a) =
-- f (x^a) . g(x^a) = (f^a . g^a) (x)@
instance (Arrow arrow, Monoid value, RAction point g) => Monoidal (FieldA arrow point value) g

--}
