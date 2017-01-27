{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Interface for cryptographically secure random byte generators.
module Raaz.Random
       ( MonadRandom(..), RandomM, reseed, fillRandomBytes, random
       , RT
       , Random(..),  unsafePokeManyRandom
       ) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Data.Int
import Data.Vector.Unboxed
import Data.Word

import Foreign.Ptr      ( Ptr     , castPtr)
import Foreign.Storable ( Storable, peek   )
import Prelude

import Raaz.Random.ChaCha20PRG
import Raaz.Core


-- | A random memory thread.
type RT  = MT RandomMem

-- | A monad that supports reseeding and picking crypto-graphically
-- secure random bytes. The monad internally has an memory element
-- where it stores the current seed. The combinator
-- `runInternalStateAction` is meant to run the action on that
-- internal thread. The MonadMemory instance should be such that the
-- `securely` and `insecurely` function should take care of seeding
-- before it starts using internal random state.
class MonadMemory m => MonadRandom m where

  -- | Run an internal state action. The
  liftRT :: RT a -> m a

-- | Reseed from the system entropy pool. Usually this is slow and
-- hence it is /not/ a good idea to reseed often.
reseed :: MonadRandom m => m ()
reseed = liftRT reseedRT

-- | Fill the given input pointer with random bytes.
fillRandomBytes :: (MonadRandom m, LengthUnit l) => l ->  Pointer -> m ()
fillRandomBytes l = liftRT . fillRandomBytesRT l

-- | Actions that uses some randomness.
newtype RandomM a = RandomM { runRandomM :: RT a } deriving (Functor, Applicative, Monad, MonadIO)


instance MonadMemory RandomM where

  insecurely randomAction = insecurely $ reseedRT >> runRandomM randomAction
  securely   randomAction = securely   $ reseedRT >> runRandomM randomAction

instance MonadRandom RandomM where
  liftRT = RandomM


-- | Instances of storables that allows poking a random element into
-- the buffer. Minimal complete definition `pokeManyRandom`.
--
-- It might appear that all storables should be an instance of this,
-- after all we know the size of the element why not write that many
-- random bytes. The reason is that for elements that are not full
-- range, i.e.  storable types of size n where not every byte pattern
-- are valid elements, for example consider 32-bit integer modulo a
-- fixed number m.
--
-- If the user is convinced that the type is full range then one can
-- use `unsafePokeManyRandom` as the definition of `pokeManyRandom`
class Storable a => Random a where

  -- | Poke a random element.
  pokeRandom :: Ptr a -> RT ()
  pokeRandom = pokeManyRandom 1

  -- | Poke multiple random element.
  pokeManyRandom :: Int -> Ptr a -> RT ()

------------------------------- Some instances of Random ------------------------
instance Random Word8 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Word16 where
  pokeManyRandom = unsafePokeManyRandom


instance Random Word32 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Word64 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Int8 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Int16 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Int32 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Int64 where
  pokeManyRandom = unsafePokeManyRandom

instance Random w => Random (LE w) where
  pokeManyRandom n = pokeManyRandom n . castLEPtr
    where castLEPtr :: Ptr (LE a) -> Ptr a
          castLEPtr = castPtr

instance Random w => Random (BE w) where
  pokeManyRandom n  = pokeManyRandom n . castBEPtr
    where castBEPtr :: Ptr (BE w) -> Ptr w
          castBEPtr = castPtr


instance (Dimension d, Unbox w, Random w) => Random (Tuple d w) where
  pokeManyRandom m ptr = pokeManyRandom (m * dimTup ptr) $ castTupPtr ptr
    where castTupPtr :: Ptr (Tuple m a) -> Ptr a
          castTupPtr = castPtr

          getElement :: Ptr (Tuple m a) -> Tuple m a
          getElement _ = undefined
          dimTup :: Dimension m => Ptr (Tuple m a) -> Int
          dimTup = dimension . getElement



-- | Pick an element. The element picked is crypto-graphically
-- pseudo-random.
random :: (Random a , MonadRandom m) => m a
random = liftRT retA
  where retA = liftAllocator alloc $ getIt . castPtr

        getIt        :: Random a => Ptr a -> RT a
        getIt ptr    = pokeRandom ptr >> liftIO (peek ptr)
        getElement   :: RT a -> a
        getElement _ = undefined

        algn         = alignment $ getElement retA
        sz           = sizeOf    $ getElement retA
        alloc        = allocaAligned algn sz


-- | The action @unsafePokeManyRandom n ptr@ pokes @n@ random elements
-- at the location starting at ptr.  If the underlying type does not
-- saturate its entire binary size (think of say Word8 modulo 5), the
-- distribution of elements can be rather skewed . Hence the prefix
-- unsafe. This function is exported to simplify the definition
-- `Random` instance. Do not use it unwisely.
unsafePokeManyRandom :: Storable a => Int -> Ptr a -> RT ()
unsafePokeManyRandom n ptr = fillRandomBytesRT totalSz $ castPtr ptr
  where totalSz = fromIntegral n * sizeOf (getElement ptr)
        getElement :: Ptr a -> a
        getElement _ = undefined
