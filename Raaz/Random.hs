{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Interface for cryptographically secure random byte generators.
module Raaz.Random
       ( -- * Cryptographically secure randomness.
         -- $randomness$
         RT, RandM
       , random, runRT
       -- * Low level functions
       , fillRandomBytes, reseed
       , unsafePokeManyRandom
       , MemoryRandom(..)
       , Random(..),
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
-- secure random bytes is captured by the monad @`RT` mem@.  It is
-- parameterised by the memory type @mem@ which should be an instance
-- of the class `MemoryRandom`.
--
-- A random action @foo :: RT mem a@ can be run to obtain an @IO@
-- using the combinator `runRT`. When the action @foo@ is used to
-- generate a long term secret, say a public-key private key pair, it
-- is better to ensure that generated randomness does not end up in
-- the swap space. In such cases we can run the action securely as
-- follows
--
-- >
-- > runRT securely foo
-- >
--
-- In the above command all allocated memory is locked to prevent it
-- from getting swapped.  On the other hand, if we do not care so much
-- about the secrecy of the generated random bytes, a more efficient
-- way would be to run it with unlocked memory.
--
-- >
-- > runRT insecurely foo
-- >
--
-- The monad `RandM` captures a batch of random action that uses only
-- the memory used to keep track of the prg.
--
-- = Internal details
--
-- Generating unpredictable stream of bytes is one task that has burnt
-- the fingers of a lot of programmers. Unfortunately, getting it
-- correct is something of a black art. As has now become standard,
-- raaz uses a stream cipher (chacha20), initialised with a starting
-- random key/iv. The starting seed is then drawn form the system
-- entropy pool.
--
-- TODO: We do not have windows support yet. On posix systems we
-- mostly @\/dev\/urandom@. However, depending on underlying operating
-- system, there are better options. The recommended way to generate
-- randomness on an OpenBSD system is through the function
-- `arc4random` (note that arc4random does not use rc4 cipher
-- anymore).  Recent Linux kernels support the `getrandom` system call
-- which unfortunately is not yet popular. These system specific calls
-- are better because they take into consideration many edge cases
-- like for example @\/dev\/urandom@ not being accessible or
-- protection from signals. Eventually we will be supporting these calls.
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
-- random bytes. The reason is that for elements that are not full
-- range, i.e.  storable types of size n where not every byte pattern
-- are valid elements, for example consider 32-bit integer modulo a
-- fixed number m.
--
-- If the user is convinced that the type is full range then one can
-- use `unsafePokeManyRandom` as the definition of `pokeManyRandom`
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
