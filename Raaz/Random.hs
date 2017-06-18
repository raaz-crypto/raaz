{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- | Interface for cryptographically secure random byte generators.
module Raaz.Random
       ( -- * Cryptographically secure randomness.
         -- $randomness$
         RandM, RT
       , randomByteString
       -- ** Types that can be generated randomly
       , RandomStorable(..), unsafeFillRandomElements, random, randomiseCell
         -- * Low level access to randomness.
       , fillRandomBytes
       , reseed
       ) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Data.ByteString             ( ByteString             )
import Data.Int
import Data.Vector.Unboxed  hiding ( replicateM, create     )
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
-- generate/use cryptographically secure random bytes. The easiest way
-- to generate a random element is to use the `random` combinator. If
-- one is interested in a sequence of random bytes, one can use the
-- `randomBytestring` combinator.
--
-- A more low level interface to cryptographic randomness is through
-- the buffer filling operations `fillRandomBytes` and
-- `fillRandomElements`. While not as convenient to use as `random`
-- and `randomByteString`, and in many ways prone to all the problems
-- with pointer functions, this should be the method of choice for
-- generating sensitive data as you can make sure that the data does
-- not end up on the swap device by using a locked memory for the
-- buffer.
--
-- = Running a random action
--
-- Depending on whether the random bytes generated are sensitive or
-- not, you can use either of the combinators `securely` or
-- `insecurely`.  The combinator `securely` ensures that the seed of
-- the PRG is stored in a locked memory and hence will not be swapped
-- out to the disk. A use case for this is when you use the random
-- bytes to generate say a long term public key. On the other hand
-- locked memory is limited on most systems. So for cases where the
-- secrecy of the bytes are not important, we would recommend using
-- `insecurely`.
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
-- == Note of caution on secure random source.
--
-- Running a random action `securely` only guarantees the seed is kept
-- in locked memory and not the generated Haskell value. For example,
-- in the following code
--
-- > genWord64 :: IO Word64
-- > genWord64 = securely random
-- >
-- > genRandomPassword :: IO ByteString
-- > genRandomPassword = securely $ randomByteString 42
--
-- the generated 64-bit word number or the password is not stored in a
-- locked memory. There is /no/ additional security gained by using
-- `securely` over `insecurely` as these values are stored in the
-- (unlocked) Haskell heap. It is not feasible to ensure that the
-- value is stored in locked memory as the garbage collector often
-- moves values around. In general, it is not good to generate sensitive values
-- as a pure Haskell values.
--
-- The main idea is to generate the random data directly inside a
-- buffer which hopefully is locked. A situation that often occur in
-- practice is to randomise the contents of a memory cell, which is
-- then used for further processing. This can be achieved by using
-- `randomiseCell` which, together with appropriate uses of
-- `onSubMemory`, should take care of most use cases. As an example,
-- consider the following fragment of code where we need to have both
-- the key and IV generated randomly and securely.
--
-- > type SensitiveInfo = (MemoryCell Key, Memory IV)
-- >
-- > genKeyAndIV = RT SenistiveInfo ()
-- > genKeyAndIV = onSubMemory fst randomiseCell
-- >               >> onSubMemory snd randomise Cell
-- >
--
-- More complicated interactions might require direct use of
-- `fillRandomBytes` but that is too low level and we do not encourage
-- its use.
--
-- = Internal details.
--
-- Generating unpredictable stream of bytes is one task that has burnt
-- the fingers of a lot of programmers. Unfortunately, getting it
-- correct is something of a black art. The pseudo-random generator in
-- Raaz uses the chacha20 stream cipher. There are two main steps in
-- the generation of random data:
--
-- [Seeding] The internal state of of the chacha20 cipher is set using the
--   system entropy.
--
-- [Sampling] An auxilary buffer is used to generate data. We called
--   this step sampling.  Requested bytes are given out from this
--   buffer. When the buffer gets empty more of the key stream is
--   generated.
--
-- The auxilary buffer and the internal chacha20 state is part of the
-- memory used in the `RT` monad and hence using this `securely` will
-- ensure that all these are allocated from locked memory.
--
-- == Seeding.
--
-- Reading the system entropy source is a costly affair because often
-- it involves a system call. Therefore, seeding is done only
-- infrequently. The security of PRG however crucially depends on the
-- system entropy source because if the seeded value is predictable
-- then till the next seeding (an infrequent event as explained above)
-- everything is deterministic and hence compromised. Raaz currently
-- hides the details of the system entropy source from the user and
-- exposes a uniform interface across platforms. It strives to use the
-- best source for the given platform. For example, we have the
-- following platform support:
--
-- [OpenBSD:] Uses the arc4random call (needs testing)
--
-- [Linux:] Defaults to @\/dev\/urandom@ but has experimental support for
-- `getrandom` (needs testing)
--
-- [Other Posix:] Uses @\/dev\/urandom@
--
-- [Windows:] No support yet. If you are windows user please consider
--    contributing.
--
-- == Sampling.
--
-- Sampling is the stage where we generate the chacha20 keystream in
-- the auxilary buffer (currenlty 16 blocks of ChaCha20). We first
-- fill the auxilary buffer with the key stream and use a total of
-- `key size + iv size` bytes to reinitialise the key iv pair. This is
-- for backward unpredictability.
--
-- On a request, we give out bytes from this auxilary buffer. The
-- portion of the auxilary buffer that is already sent out is
-- wiped. If there is not enough in the auxilary buffer, we sample
-- again and continue the process till the necessary number of bytes
-- are given out.


-- | A batch of actions on the memory element @mem@ that uses some
-- randomness.
newtype RT mem a = RT { unRT :: MT (RandomState, mem) a }
                 deriving (Functor, Applicative, Monad, MonadIO)

-- | Run a randomness thread. In particular, this combinator takes
-- care of seeding the internal prg at the start.
seedAndRunRT :: RT m a
      -> MT (RandomState, m) a
seedAndRunRT action = onSubMemory fst reseedMT >> unRT action

-- | The monad for generating cryptographically secure random data.
type RandM = RT VoidMemory

instance MemoryThread RT where
  insecurely        = insecurely . seedAndRunRT
  securely          = securely   . seedAndRunRT
  liftMT            = RT . onSubMemory snd
  onSubMemory proj  = RT . onSubMemory projP . unRT
    where projP (rstate, mem) = (rstate, proj mem)
          -- No (misguided) use of functor instance for (,) here.

-- | Reseed from the system entropy pool. There is never a need to
-- explicitly seed your generator. The insecurely and securely calls
-- makes sure that your generator is seed before
-- starting. Furthermore, the generator also reseeds after every few
-- GB of random bytes that it generates. Generating random data from
-- the system entropy is usually an order of magnitude slower than
-- using a fast stream cipher. Reseeding often can slow your program
-- considerably without any additional security advantage.
--
reseed :: RT mem ()
reseed = RT $ onSubMemory fst reseedMT

-- | Fill the given input pointer with random bytes.
fillRandomBytes :: LengthUnit l => l ->  Pointer -> RT mem ()
fillRandomBytes l = RT . onSubMemory fst . fillRandomBytesMT l


-- | Instances of `Storable` which can be randomly generated. It might
-- appear that all storables can easily be generated randomly should
-- be instances of this class, after all we know the size of the
-- element why not write that many random bytes. In fact, this module
-- provides an `unsafeFillRandomElements` which does that. However, we
-- do not give a blanket definition for all storables because for
-- certain refinements of a given type, like for example, Word8's
-- modulo 10, `unsafeFillRandomElements` introduces unacceptable
-- skews.
class Storable a => RandomStorable a where
  -- | Fill the buffer with so many random elements of type a.
  fillRandomElements :: Memory mem
                     => Int       -- ^ number of elements to fill
                     -> Ptr a     -- ^ The buffer to fill
                     -> RT mem ()


-- | This is a helper function that has been exported to simplify the
-- definition of a `RandomStorable` instance for `Storable`
-- types. However, there is a reason why we do not give a blanket
-- instance for all instances `Storable` and why this function is
-- unsafe? This function generates a random element of type @a@ by
-- generating @n@ random bytes where @n@ is the size of the elements
-- of @a@. For instances that range the entire @n@ byte space this is
-- fine. However, if the type is actually a refinement of such a type,
-- (consider a @`Word8`@ modulo @10@ for example) this function
-- generates an unacceptable skew in the distribution. Hence this
-- function is prefixed unsafe.
unsafeFillRandomElements :: (Memory mem, Storable a) => Int -> Ptr a -> RT mem ()
unsafeFillRandomElements n ptr = fillRandomBytes totalSz $ castPtr ptr
  where totalSz = fromIntegral n * sizeOf (getElement ptr)
        getElement :: Ptr a -> a
        getElement _ = undefined


-- | Generate a random element from an instance of a RandomStorable
-- element.
random :: (RandomStorable a, Memory mem) => RT mem a
random = RT $ liftPointerAction alloc (getIt . castPtr)
  where getIt ptr    = unRT $ fillRandomElements 1 ptr >> liftIO (peek ptr)
        alloc        :: Storable a => (Pointer -> IO a) -> IO a
        alloc action = allocaAligned algn sz action
          where getElement   :: (Pointer -> IO b) -> b
                getElement _ = undefined
                thisElement  = getElement action
                algn         = alignment thisElement
                sz           = sizeOf    thisElement

-- | Randomise the contents of a memory cell. Equivalent to @`random`
-- >>= liftMT . initialise@ but ensures that no data is transferred to
-- unlocked memory.
randomiseCell :: RandomStorable a => RT (MemoryCell a) ()
randomiseCell = getCellPointer >>= fillRandomElements 1

-- | Generate a random byteString.

randomByteString :: LengthUnit l
                 => l
                 -> RT mem ByteString
randomByteString l = RT $ onSubMemory fst  $ liftPointerAction (create l) $ fillRandomBytesMT l

------------------------------- Some instances of Random ------------------------

instance RandomStorable Word8 where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable Word16 where

  fillRandomElements = unsafeFillRandomElements

instance RandomStorable Word32 where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable Word64 where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable Word where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable Int8 where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable Int16 where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable Int32 where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable Int64 where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable Int where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable KEY where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable IV where
  fillRandomElements = unsafeFillRandomElements

instance RandomStorable w => RandomStorable (LE w) where
  fillRandomElements n = fillRandomElements n . lePtrToPtr
    where lePtrToPtr :: Ptr (LE w) -> Ptr w
          lePtrToPtr = castPtr

instance RandomStorable w => RandomStorable (BE w) where
  fillRandomElements n = fillRandomElements n . bePtrToPtr
    where bePtrToPtr :: Ptr (BE w) -> Ptr w
          bePtrToPtr = castPtr

instance (Dimension d, Unbox w, RandomStorable w) => RandomStorable (Tuple d w) where
  fillRandomElements n ptr = fillRandomElements (n * sz) $ tupPtrToPtr ptr
    where getTuple    :: Dimension d => Ptr (Tuple d w) -> Tuple d w
          getTuple _  = undefined
          tupPtrToPtr ::  Ptr (Tuple d w) -> Ptr w
          tupPtrToPtr = castPtr
          sz         = dimension $ getTuple ptr
