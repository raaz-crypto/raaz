{-|

Generic cryptographic primtives and gadgets computing them. This is
the low-level stuff that lies in the guts of the raaz system. You
might be better of using the more high leven interface.

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
       , SafeGadget(..)
       , UnsafeGadget(..)
       , CryptoPrimitive(..)
       , HasPadding(..)
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
-- stuff: primitives and gadgets to compute those primitives. Typical
-- cryptographic primitives are hashes, macs, ciphers, signature
-- algorithms etc. A gadget can be thought of as a device or algorithm
-- that implements the primitive.
--
-- As a library, raaz believes in providing multiple gadgets for a
-- primitive. Of these two are of at most importance. There is the
-- reference gadget where the emphasis is on correctness rather than
-- speed or security. They are used to verify the correctness of the
-- other gadgets for the same primitive. For use of production, there
-- is the recommended gadget which. By default all library functions
-- are tuned to use the recommended gadget.
--

----------------------- A primitive ------------------------------------

-- | Abstraction that captures crypto primitives. A primitive consists
-- of the following (1) A block size (2) and intialisation value
-- (captures by `IV`) and (3) a finalisation value captured `FV`. For
-- a stream primitive (like a stream cipher) the block size is
-- 1. Certain primitives do not require an initialisation value
-- (e.g. a hash) or might not provide a final value (e.g. a
-- cipher). In such cases use the unit type `()`.

class Primitive p where

  blockSize :: p -> BYTES Int -- ^ Block size

  data IV p :: * -- ^ the initialisation value.

-----------------   A cryptographic gadget. ----------------------------

-- | A gadget implements a primitive It has three phases: (1) the
-- initialisation (2) the processing/transformation phase and (3) the
-- finalisation. Depending on what the gadget does each of this phase
-- might be absent/trivial. The main action happens in the processing
-- phase where the gadget is passed a buffer. Depending on the
-- functionality of the gadget data is either written into/read by/or
-- transformed (think of a PRG, Cryptographic hash or a Cipher
-- respectively).
--
class ( Primitive (PrimitiveOf g), Memory (MemoryOf g) )
      => Gadget g where

  type PrimitiveOf g

  type MemoryOf g

  -- | Creates a new gadget using the provided memory.
  newGadget :: (MemoryOf g) -> IO g

  -- | Initializes the gadget.
  initialize :: g -> IV (PrimitiveOf g) -> IO ()

  -- | Finalize the data. Whether the gadget can be used again is
  -- gadget dependent.
  finalize :: g -> IO (PrimitiveOf g)

  -- | The recommended number of blocks to process at a time. While
  -- processing files, bytestrings it makes sense to handle multiple
  -- blocks at a time. Setting this member appropriately (typically
  -- depends on the cache size of your machine) can drastically
  -- improve cache performance of your program. Default setting is the
  -- number of blocks that fit in @32KB@.
  recommendedBlocks   :: g -> BLOCKS (PrimitiveOf g)
  recommendedBlocks _ = cryptoCoerce (1024 * 32 :: BYTES Int)


class (Gadget g) => SafeGadget g where
    -- | Performs the action of the gadget on the buffer. The
    -- instances of this class must ensure that the data in the
    -- message buffer is left intact.
  applySafe :: g -> BLOCKS (PrimitiveOf g) -> CryptoPtr -> IO ()

class (Gadget g) => UnsafeGadget g where
    -- | Performs the action of the gadget on the buffer. The
    -- instances of this class can modify the data in the
    -- message buffer.
  applyUnsafe :: g -> BLOCKS (PrimitiveOf g) -> CryptoPtr -> IO ()

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
                -> (g -> (BLOCKS (PrimitiveOf g)) -> CryptoPtr -> IO ())
                -> src       -- ^ The byte source
                -> IO ()
{-# INLINEABLE transformGadget #-}

transformGadget g apply src = allocaBuffer bufSize $ go 0 src
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
                    -> (g -> (BLOCKS (PrimitiveOf g)) -> CryptoPtr -> IO ())
                    -> FilePath   -- ^ The file name.
                    -> IO ()
transformGadgetFile g apply fpth = withFile fpth ReadMode $ transformGadget g apply
{-# INLINEABLE transformGadgetFile #-}
