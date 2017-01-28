{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Interface for cryptographically secure random byte generators.
module Raaz.Random
       ( -- * Cryptographically secure randomness.
         -- $randomness$
         RT, RandM, random
       , Random(..)
       , MemoryRandom(..)
       -- * Low level functions
       , fillRandomBytes, reseed
       , unsafePokeManyRandom
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

-- $randomness$
--
-- The raaz library gives a relatively high level interface to
-- randomness. A batch of actions that generate/use cryptographically
-- secure random bytes is captured by the monad @`RT` mem@. The
-- parameter @mem@ needs to be an instance of `MemoryRandom`, which
-- essentially asserts @mem@, besides other things, stores the
-- internal state of the pseudo-random generator.
--
-- == Running random action.
--
-- The @`RT` mem@ monad is an instance of @MonadMemory@ whenever @mem@
-- is a an instance of @MonadRandom@. Therefore, one can run it either
-- `securely` or `insecurely`
--
-- = Internal details
--
-- Generating unpredictable stream of bytes is one task that has burnt
-- the fingers of a lot of programmers. Unfortunately, getting it
-- correct is something of a black art.  Raaz uses a stream cipher
-- (chacha20), initialised with a starting random key/iv. The starting
-- seed is then drawn from the system entropy pool.
--
-- TODO: For system entropy we use @\/dev\/urandom@ on a posix systems
-- (no windows support yet). Even on posix systems, depending on
-- underlying operating system, there are better options. The
-- recommended way to generate randomness on an OpenBSD system is
-- through the function `arc4random` (note that arc4random does not
-- use rc4 cipher anymore).  Recent Linux kernels support the
-- `getrandom` system call which unfortunately is not yet
-- popular. These system specific calls are better because they take
-- into consideration many edge cases like for example
-- @\/dev\/urandom@ not being accessible or protection from interrupts
-- Eventually we will be supporting these calls.
--

-- | A batch of actions on the memory element m that uses some
-- randomness.
newtype RT m a = RT { unMT :: MT m a } deriving (Functor, Applicative, Monad, MonadIO)

-- | The monad for generating cryptographically secure random data.
type RandM = RT RandomState

-- | Run a randomness thread. This combinator takes care of seeding
-- the internal prg before running it and as such is not required to
-- be seeded.
runRT :: MemoryRandom m
     => (MT m a -> IO a) -- ^ How to run it (securely/insecurely)
     -> RT m a
     -> IO a
runRT runner action = runner runIt
  where runIt = onSubMemory randomState reseedMT >> unMT action

instance MemoryRandom mem => MonadMemory (RT mem) where
  insecurely = runRT insecurely
  securely   = runRT securely

-- | A memory element which contains a sub-memory for randomness.
class Memory mem => MemoryRandom mem where

  -- | Recover the internal random state.
  randomState :: mem -> RandomState


instance MemoryRandom RandomState where
  randomState = id

-- | Reseed from the system entropy pool. Usually this is slow and
-- hence it is better /not/ reseed often.
reseed :: MemoryRandom mem => RT mem ()
reseed = RT $ onSubMemory randomState reseedMT

-- | Fill the given input pointer with random bytes.
fillRandomBytes :: (MemoryRandom mem, LengthUnit l) => l ->  Pointer -> RT mem ()
fillRandomBytes l = RT . onSubMemory randomState . fillRandomBytesMT l


-- | Instances of storables that allows poking a random element into
-- the buffer. Minimal complete definition `pokeManyRandom`.
--
-- It might appear that all storables should be an instance of this,
-- after all we know the size of the element why not write that many
-- random bytes. In fact this module provides an
-- `unsafePokeManyRandom` which essentially does exactly
-- that. However, we do not give a blanket definition for all
-- storables because for certain refinements of a given type, like for
-- example, Word8's modulo 10, `unsafePokeManyRandom` introduces
-- unacceptable skews.
--
class Storable a => Random a where

  -- | Poke a random element.
  pokeRandom :: Ptr a -> MT RandomState ()
  pokeRandom = pokeManyRandom 1

  -- | Poke multiple random element.
  pokeManyRandom :: Int -> Ptr a -> MT RandomState ()

-- | Pick an element. The element picked is crypto-graphically
-- pseudo-random.
random :: (MemoryRandom mem, Random a) => RT mem a
random = RT $ onSubMemory randomState retA
  where retA = liftAllocator alloc $ getIt . castPtr

        getIt        :: Random a => Ptr a -> MT RandomState a
        getIt ptr    = pokeRandom ptr >> liftIO (peek ptr)
        getElement   :: MT RandomState a -> a
        getElement _ = undefined

        algn         = alignment $ getElement retA
        sz           = sizeOf    $ getElement retA

        alloc        = allocaAligned algn sz


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




-- | The action @unsafePokeManyRandom n ptr@ pokes @n@ random elements
-- at the location starting at ptr.  If the underlying type does not
-- saturate its entire binary size (think of say Word8 modulo 5), the
-- distribution of elements can be rather skewed . Hence the prefix
-- unsafe. This function is exported to simplify the definition
-- `Random` instance. Do not use it unwisely.
unsafePokeManyRandom :: Storable a => Int -> Ptr a -> MT RandomState ()
unsafePokeManyRandom n ptr = fillRandomBytesMT totalSz $ castPtr ptr
  where totalSz = fromIntegral n * sizeOf (getElement ptr)
        getElement :: Ptr a -> a
        getElement _ = undefined
