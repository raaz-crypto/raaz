-- | Processing data in buffers involve a lot of pointer
-- gymnastics. This module provide a framework to perform some of them
-- cleanly and safely. One can use

{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE FlexibleInstances          #-}
module Raaz.Core.Gymnastics
       ( Manoeuvre(..)
       , manoeuvre
       -- * Applicative parsing manoeuvre

       -- * Monoidal Writing Manoeuvre
       ) where
import Control.Applicative
import Data.Monoid

import Raaz.Core.Types
import Raaz.Core.Util.Ptr (movePtr)

-- | The type @Manoeuvre l m a@ is a gymnastic manoeuvre involving a
-- pointer.  As the name suggests a gymnastic is tricky and dangerous
-- and should be done with care. However, Haskell types make it easy
-- to keep things safe. The parameter @m@ is typically a monad (mostly
-- IO) which corresponds to the action taken. Each manoeuvre affects
-- certain bytes at the location where it is applied. The type
-- argument @l@ is a length units in which we measure the amount of
-- data effected.
data Manoeuvre l m a =
  Manoeuvre { sizeAffected :: !l
                              -- ^ The size of data that is affected by this
                              -- gymnastic manoeuvre.
            , unsafeManoeuvre :: CryptoPtr -> m a
                              -- The actual pointer gymnastic.
            }

instance Functor m => Functor (Manoeuvre l m) where
  fmap f (Manoeuvre l act) = Manoeuvre l $ (\ cptr -> fmap f $ act cptr)

instance (LengthUnit l, Applicative m) => Applicative (Manoeuvre l m) where
  pure = Manoeuvre 0 . const . pure
  (<*>) mf ma = Manoeuvre faSize mfa
    where mfa = \ fptr -> unsafeManoeuvre mf fptr <*> unsafeManoeuvre ma (fptr `movePtr` fSize)
          fSize    = sizeAffected mf
          aSize    = sizeAffected ma
          faSize   = fSize + aSize

-- | When the return value of the action is not relevant Manoeuvres are monoids as well.
instance (LengthUnit l, Applicative m) => Monoid (Manoeuvre l m ()) where
  mempty = pure ()
  mappend m1 m2 = m1 <* m2
  mconcat = foldl mempty *> mempty

-- | Run a manoeuvre on a cryptobuffer.
manoeuvre :: LengthUnit l => Manoeuvre l IO a -> CryptoBuffer -> IO (Maybe a)
manoeuvre mA cbuf = withCryptoBuffer cbuf $ \ sz cptr ->
  if sz < inBytes (sizeAffected mA) then pure Nothing
  else Just <$> unsafeManoeuvre mA cptr
