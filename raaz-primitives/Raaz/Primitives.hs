{-|

Generic cryptographic primtives and gadgets computing them. This is
the low-level stuff that lies in the guts of the raaz system. You
might be better of using the more high level interface.

-}

{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE MultiParamTypeClasses       #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
{-# LANGUAGE FlexibleContexts            #-}

module Raaz.Primitives
       ( -- * Primtives and gadgets.
         -- $primAndGadget$
         Primitive(..)
       , Gadget(..)
       , SafeGadget
       , CryptoPrimitive(..)
       , HasPadding(..)
         -- * Type safe length units.
       , BLOCKS, blocksOf
       , transformGadget, transformGadgetFile
       ) where

import qualified Data.ByteString      as B
import           Data.ByteString.Internal(unsafeCreate)
import           Data.Word(Word64)
import           Foreign.Ptr(castPtr)
import           System.IO(withFile, IOMode(ReadMode))

import Raaz.Memory
import Raaz.Types
import Raaz.ByteSource
import Raaz.Util.ByteString
import Raaz.Util.Ptr

-- $primAndGadget$
--
-- The raaz cryptographic engine is centered around two kinds of
-- stuff: (1) /primitives/ and (2) /gadgets/ to compute those
-- primitives. Typical cryptographic primitives are hashes, macs,
-- ciphers, signature algorithms etc. A gadget can be thought of as a
-- device or algorithm that implements the primitive. However, it is
-- not merely a function. Usually they have internal memory elements
-- or associated with them and they require explicit initialisation
-- and finalisation. Therefore the device analogy is often better.
--
-- As a library, raaz believes in providing multiple gadgets for a
-- given primitive. Of these two are of at most importance. There is
-- the /reference gadget/ where the emphasis is on correctness rather
-- than speed or security. They are used to verify the correctness of
-- the other gadgets for the same primitive. For use of production,
-- there is the /recommended gadget/. By default all library functions
-- are tuned to use the recommended gadget.
--

----------------------- A primitive ------------------------------------

-- | Abstraction that captures crypto primitives. Every primitive that
-- that we provide is a type which is an instance of this class. A
-- primitive consists of the following (1) A block size and (2) an
-- intialisation value (captured by the data family `IV`). For a
-- stream primitive (like a stream cipher) the block size is 1.
--
-- When dealing with buffer lengths for a primitive, it is often
-- better to use the type safe units `BLOCKS`. Functions in the raaz
-- package that take lengths usually allow any type safe length as
-- long as they can be converted to bytes. This can avoid a lot of
-- tedious and error prone length calculations.
class Primitive p where

  -- | The block size.
  blockSize :: p -> BYTES Int

  -- | The initialisation value.
  data IV p :: *

-----------------   A cryptographic gadget. ----------------------------

-- | A gadget implements a primitive. It has three phases: (1) the
-- initialisation (2) the /processing/ or /transformation/ phase and
-- (3) the /finalisation/. Depending on what the gadget, i.e. the
-- nature of the associated primitive, each of this phase might be
-- absent or trivial. The main action happens in the processing phase
-- where the gadget is passed a buffer. Depending on the functionality
-- of the gadget data is either written into, or read by or just
-- transformed (think of a PRG, Cryptographic hash or a Cipher
-- respectively).
--
class ( Primitive (PrimitiveOf g), Memory (MemoryOf g) )
      => Gadget g where

  -- | The primitive for which this is a gadget
  type PrimitiveOf g

  -- | The (type of the) internal memory used by the gadget.
  type MemoryOf g

  -- | The action @newGadget mem@ creates a gadget which uses @mem@ as
  -- its internal memory. If you want the internal data to be
  -- protected from being swapped out (for example if the internal
  -- memory contains sensitive data) then pass a secuded memory to
  -- this function.
  newGadget :: (MemoryOf g) -> IO g

  -- | Initializes the gadget.
  initialize :: g -> IV (PrimitiveOf g) -> IO ()

  -- | Finalize the data.
  finalize :: g -> IO (PrimitiveOf g)

  -- | The recommended number of blocks to process at a time. While
  -- processing files, bytestrings it makes sense to handle multiple
  -- blocks at a time. Setting this member appropriately (typically
  -- depends on the cache size of your machine) can drastically
  -- improve cache performance of your program. Default setting is the
  -- number of blocks that fit in @32KB@.
  recommendedBlocks   :: g -> BLOCKS (PrimitiveOf g)
  recommendedBlocks _ = cryptoCoerce (1024 * 32 :: BYTES Int)

  -- | This function actually applies the gadget on the buffer. What
  -- happens to the content of the buffer depends on whether it is a
  -- `SafeGadget` or not.
  apply :: g -> BLOCKS (PrimitiveOf g) -> CryptoPtr -> IO ()

-- | A gadget @g@ is a safe gadget if it does not modify its input
-- buffer. For example, gadgets for hashes are usually safe (there is
-- no requirement as such but it appears that it makes sense to keep
-- it safe) where as one would not want the a cipher gadget or a
-- random source gadget to be safe. This type class captures a gadget
-- that promises not to touch the the buffer of data that it
-- processes. If we want to compute two primitives on the same data,
-- then using a safe gadget for the first primitive ensures that we do
-- not need to recopy the actual source (consider for example hmac
-- followed by encryption).
class (Gadget g) => SafeGadget g


-------------------- Primitives with padding ---------------------------

-- | Block primitives have a padding method. The obvious reason for
-- padding is to handle messages that are not multiples of the block
-- size. However, there is a more subtle reason. For certain hashing
-- schemes like Merkel-Damgård, the strength of the hash crucially
-- depends on the padding.
--
-- The minimal complete definition include `padLength`,
-- `maxAdditionalBlocks` and one of `padding` or `unsafePad`.
--

class Primitive p => HasPadding p where

  -- | This combinator returns the length of the padding that is to be
  -- added to the message.
  padLength :: p           -- ^ the block primitive
            -> BITS Word64 -- ^ the total message size in bits.
            -> BYTES Int

  -- | This function returns the actual bytestring to pad the message
  -- with. There is a default definition of this message in terms of
  -- the unsafePad function. However, implementations might want to
  -- give a more efficient definition.
  padding   :: p           -- ^ the block primitive
            -> BITS Word64 -- ^ the total message size in bits.
            -> B.ByteString
  padding p bits = unsafeCreate len padIt
        where BYTES len = padLength p bits
              padIt     = unsafePad p bits . castPtr

  -- | This is the unsafe version of the padding function. It is
  -- unsafe in the sense that the call @unsafePad h bits cptr@ assumes
  -- that there is enough free space to put the padding string at the
  -- given pointer.
  unsafePad :: p           -- ^ the block primitive
            -> BITS Word64 -- ^ the total message size in bits
            -> CryptoPtr   -- ^ the message buffer
            -> IO ()
  unsafePad p bits = unsafeCopyToCryptoPtr $ padding p bits

  -- | This counts the number of additional blocks required so that
  -- one can hold the padding. This function is useful if you want to
  -- know the size to be allocated for your message buffers.
  maxAdditionalBlocks :: p -> BLOCKS p

---------------------- A crypto primitive ------------------------------

-- | A crypto primitive is a primitive together with a recommended
-- implementation.
class ( Gadget (Recommended p)
      , Gadget (Reference p)
      , p ~ PrimitiveOf (Recommended p)
      , p ~ PrimitiveOf (Reference p)
      ) => CryptoPrimitive p where
  type Recommended p :: *
  type Reference   p :: *

------------------- Type safe lengths in units of block ----------------

-- | Type safe message length in units of blocks of the primitive.
newtype BLOCKS p = BLOCKS Int
                 deriving (Show, Eq, Ord, Enum, Real, Num, Integral)


instance ( Primitive p
         , Num by
         ) => CryptoCoerce (BLOCKS p) (BYTES by) where
  cryptoCoerce b@(BLOCKS n) = fromIntegral $ blockSize (prim b) *
                                           fromIntegral n
         where prim :: BLOCKS p -> p
               prim _ = undefined
  {-# INLINE cryptoCoerce #-}


instance ( Primitive p
         , Num bits
         ) => CryptoCoerce (BLOCKS p) (BITS bits) where
  cryptoCoerce b@(BLOCKS n) = fromIntegral $ 8 * blockSize (prim b) *
                                           fromIntegral n
         where prim :: BLOCKS p -> p
               prim _ = undefined
  {-# INLINE cryptoCoerce #-}

-- | BEWARE: There can be rounding errors if the number of bytes is
-- not a multiple of block length.
instance ( Primitive p
         , Integral by
         ) => CryptoCoerce (BYTES by) (BLOCKS p) where
  cryptoCoerce bytes = result
         where prim :: BLOCKS p -> p
               prim _ = undefined
               result = BLOCKS (fromIntegral m)
               m      = fromIntegral bytes `quot` blockSize (prim result)
  {-# INLINE cryptoCoerce #-}

-- | BEWARE: There can be rounding errors if the number of bytes is
-- not a multiple of block length.
instance ( Primitive p
         , Integral by
         ) => CryptoCoerce (BITS by) (BLOCKS p) where
  cryptoCoerce = cryptoCoerce . bytes
    where bytes :: Integral by => BITS by -> BYTES by
          bytes = cryptoCoerce
  {-# INLINE cryptoCoerce #-}
-- | The expression @n `blocksOf` p@ specifies the message lengths in
-- units of the block length of the primitive @p@. This expression is
-- sometimes required to make the type checker happy.
blocksOf :: Primitive p =>  Int -> p -> BLOCKS p
blocksOf n _ = BLOCKS n

-------------------- Some helper functions -----------------------------

-- | For a block primitive that supports padding, this combinator is
-- used when we care only about the final context and not the contents
-- of the procesed buffer.
transformGadget :: ( ByteSource src
                   , Gadget g
                   , HasPadding (PrimitiveOf g)
                   )
                => g         -- ^ Gadget
                -> src       -- ^ The byte source
                -> IO ()
{-# INLINEABLE transformGadget #-}

transformGadget g src = allocaBuffer bufSize $ go 0 src
  where nBlocks = recommendedBlocks g
        bufSize = nBlocks + maxAdditionalBlocks p
        p       = getPrimitive g
        getPrimitive :: Gadget g => g -> PrimitiveOf g
        getPrimitive _ = undefined
        go k source cptr =   fill nBlocks source cptr
                             >>= withFillResult continue endIt
           where continue rest = do apply g nBlocks cptr
                                    go (k + nBlocks) rest cptr
                 endIt r       = do unsafePad p bits padPtr
                                    apply g blks cptr
                       where len    = cryptoCoerce nBlocks - r
                             bits   = cryptoCoerce k + cryptoCoerce len
                             padPtr = cptr `movePtr` len
                             blks   = cryptoCoerce $ len + padLength p bits

-- | A version of `transformContext` which takes a filename instead.
transformGadgetFile :: ( Gadget g
                       , HasPadding (PrimitiveOf g)
                       )
                    => g          -- ^ Gadget
                    -> FilePath   -- ^ The file name.
                    -> IO ()
transformGadgetFile g fpth = withFile fpth ReadMode $ transformGadget g
{-# INLINEABLE transformGadgetFile #-}
