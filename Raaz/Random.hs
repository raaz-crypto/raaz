{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Interface for cryptographically secure random byte generators.
module Raaz.Random
       ( -- * Cryptographically secure randomness.
         -- $randomness$
         RandM, RT, liftMT
       , random, randomByteString
       -- ** Types that can be generated randomly
       , Random(..)
         -- * Low level access to randomness.
       , RandomState
       , fillRandomBytes
       , unsafePokeManyRandom
       , reseed

       ) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Data.ByteString            ( ByteString, pack       )
import Data.Int
import Data.Vector.Unboxed hiding ( replicateM )
import Data.Word

import Foreign.Ptr      ( Ptr     , castPtr)
import Foreign.Storable ( Storable, peek   )
import Prelude

import Raaz.Core
import Raaz.Cipher.ChaCha20.Internal(KEY, IV)
import Raaz.Random.ChaCha20PRG


-- $randomness$
--
-- The raaz library gives a relatively high level interface to
-- randomness. The monad `RandM` captures a batch of actions that
-- generate/use cryptographically secure random bytes. In particular,
-- you can use the functions `random` and `randomByteString` to
-- actually generate random elements.
--
-- The monad `RandM` is an an instance of `MonadMemory` and hence can
-- be run either `securely` or `insecurely`. Here are some examples.
--
-- > -- Generate a pair of random Word8's
-- > import Raaz
-- > import Data.Word
-- >
-- > main :: IO ()
-- > main = insecurely rPair >>= print
-- >    where rPair :: RandM (Word8, Word8)
-- >          rPair = (,) <$> random <$> random
-- >
--
--
-- > -- A version of hello world that has gone nuts. Printed in base16
-- > -- to save some terminal grief.
-- >
-- > main = insecurely who >>= \ w -> putStrLn $ "hello " ++ showBase16 w
-- >   where who :: RandM ByteString
-- >         who = randomByteString 10
-- >
--
-- Some times you need additional memory to keep track of other
-- stuff. The monad @`RT` mem@ is meant for such uses. It should be
-- seen as the analogue of the monad @`MT` mem@ which in addition
-- allows you to pick cryptographically secure random data. In fact,
-- the combinator `liftMT` allows you to lift an `MT` action to the
-- corresponding `RT` action.
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



-- | A batch of actions on the memory element @mem@ that uses some
-- randomness.
newtype RT mem a = RT { unMT :: MT (RandomState, mem) a }
                 deriving (Functor, Applicative, Monad, MonadIO)

-- | The monad for generating cryptographically secure random data.
type RandM = RT VoidMemory

-- | Lift a memory action to the corresponding RT action.
liftMT :: MT mem a -> RT mem a
liftMT = RT . onSubMemory snd

-- | Run a randomness thread. In particular, this combinator takes
-- care of seeding the internal prg at the start.
runRT :: RT m a
      -> MT (RandomState, m) a
runRT action = onSubMemory fst reseedMT >> unMT action



instance Memory mem => MonadMemory (RT mem) where
  insecurely = insecurely . runRT
  securely   = securely   . runRT

-- | Reseed from the system entropy pool. There is never a need to
-- explicitly seed your generator. The insecurely and securely calls
-- makes sure that your generator is seed before starting. Reseeding
-- often can slow your program considerably.
reseed :: RT mem ()
reseed = RT $ onSubMemory fst reseedMT

-- | Fill the given input pointer with random bytes.
fillRandomBytes :: LengthUnit l => l ->  Pointer -> RT mem ()
fillRandomBytes l = RT . onSubMemory fst . fillRandomBytesMT l


-- | Instances of storables that allows poking a random element into
-- the buffer. Minimal complete definition `pokeManyRandom`.
--
-- It might appear that all storables should be an instance of this,
-- after all we know the size of the element why not write that many
-- random bytes. In fact, this module provides an
-- `unsafePokeManyRandom` which does exactly that. However, we do not
-- give a blanket definition for all storables because for certain
-- refinements of a given type, like for example, Word8's modulo 10,
-- `unsafePokeManyRandom` introduces unacceptable skews.
--
class Storable a => Random a where

  -- | Poke a random element.
  pokeRandom :: Ptr a -> MT RandomState ()
  pokeRandom = pokeManyRandom 1

  -- | Poke multiple random element.
  pokeManyRandom :: Int -> Ptr a -> MT RandomState ()

-- | Generate a random element. The element picked is
-- crypto-graphically pseudo-random.
random :: (Memory mem, Random a) => RT mem a
random = RT $ onSubMemory fst retA
  where retA = liftAllocator alloc $ getIt . castPtr

        getIt        :: Random a => Ptr a -> MT RandomState a
        getIt ptr    = pokeRandom ptr >> liftIO (peek ptr)
        getElement   :: MT RandomState a -> a
        getElement _ = undefined

        algn         = alignment $ getElement retA
        sz           = sizeOf    $ getElement retA

        alloc        = allocaAligned algn sz


-- | Generate a random byteString.
randomByteString :: (Memory mem, LengthUnit l)
                 => l
                 -> RT mem ByteString
randomByteString l = pack <$> replicateM n random
  where n = fromIntegral $ inBytes l

------------------------------- Some instances of Random ------------------------
instance Random Word8 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Word16 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Word32 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Word64 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Word where
  pokeManyRandom = unsafePokeManyRandom

instance Random Int8 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Int16 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Int32 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Int64 where
  pokeManyRandom = unsafePokeManyRandom

instance Random Int where
  pokeManyRandom = unsafePokeManyRandom

instance Random KEY where
  pokeManyRandom = unsafePokeManyRandom

instance Random IV where
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
