{-|

Generic cryptographic primtives and gadgets computing them. This is
the low-level stuff that lies in the guts of the raaz system. You
might be better of using the more high level interface.

-}

{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE MultiParamTypeClasses       #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
{-# LANGUAGE FlexibleContexts            #-}
{-# LANGUAGE DefaultSignatures           #-}
{-# LANGUAGE CPP                         #-}


module Raaz.Core.Primitives
       ( -- * Primtives and gadgets.
         -- $primAndGadget$

         -- * Type safe lengths in units of blocks.
         -- $typesafelengths$

         Primitive(..), SafePrimitive, Gadget(..)
       , primitiveOf, withGadget, withGadgetFinalize, withSecureGadget, withSecureGadgetFinalize
       , PaddableGadget(..)
       , CGadget(..), HGadget(..)
       , HasPadding(..)
       , CryptoPrimitive(..)
       , BLOCKS, blocksOf
       , transformGadget, transformGadgetFile
       , CryptoInverse(..), inverse
         -- * Cryptographic operation modes
       , Mode(..)
       ) where

import           Control.Applicative
import qualified Data.ByteString          as B
import           Data.ByteString.Internal (unsafeCreate)
import           Data.Word                (Word64)
import           Foreign.Ptr              (castPtr)
import           System.IO                (withFile, IOMode(ReadMode))

import           Raaz.Core.ByteSource
import           Raaz.Core.Memory
import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString
import           Raaz.Core.Types.Pointer
import           Raaz.System.Parameters  (l1Cache)

-- $primAndGadget$
--
-- The raaz cryptographic engine is centered around two kinds of
-- stuff: (1) /primitives/ and (2) /gadgets/ to compute those
-- primitives. Typical cryptographic primitives are hashes, macs,
-- ciphers, signature algorithms etc. A gadget is a device or
-- algorithm that implements the primitive. However, it is not merely
-- a function. Often, they have internal memory elements associated
-- with them and require explicit initialisation and
-- finalisation. Therefore the device analogy is often better.
--
-- As a library, raaz believes in providing multiple gadgets for a
-- given primitive. Of these two are of at most importance. There is
-- the /reference gadget/ where the emphasis is on correctness rather
-- than speed or security. They are used to verify the correctness of
-- the other gadgets for the same primitive. For use in production,
-- there is the /recommended gadget/. By default all library functions
-- are tuned to use the recommended gadget.
--


----------------------- A primitive ------------------------------------

-- | Abstraction that captures a crypto primitives. Every primitive
-- that that we provide is a type which is an instance of this
-- class. A primitive consists of the following (1) A block size and
-- (2) an intialisation value (captured by the data family `Key`). For
-- a stream primitive (like a stream cipher) the block size is 1.
--
class Primitive p where

  -- | The block size.
  blockSize :: p -> BYTES Int

  -- | The key used to initialise the gadget of the primitive.
  type Key p :: *

-- | A safe primitive is a primitive whose computation does not need
-- modification of the input. Examples of safe primitives are
-- cryptographic hashes and macs. An example of an unsafe primitive is
-- cipher. A library writer is required to ensure that a `apply`
-- function of a gadget for a safe primitive should not modify the
-- input buffer.
class Primitive p => SafePrimitive p where

-----------------   A cryptographic gadget. ----------------------------

-- | A gadget implements a primitive. It has three phases: (1) the
-- initialisation (2) the /processing/ or /transformation/ phase and
-- (3) the /finalisation/. The main action happens in the processing
-- phase which is captured by the `apply` combinator. Depending on the
-- primitive, data is either written into, or read by or just
-- transformed (think of a PRG, Cryptographic hash or a Cipher
-- respectively). Gadgets are stateful and hence instances of `Memory`
-- themselves
--
-- Gadget instances where the underlying primitive is an instance of
-- `SafePrimitive` should ensure that the input buffer is not
-- modified.

class ( Primitive (PrimitiveOf g)
      , Memory g
      , InitializableMemory g
      , Key (PrimitiveOf g) ~ IV g
      ) => Gadget g where

  -- | The primitive for which this is a gadget
  type PrimitiveOf g

  -- | This function actually applies the gadget on the buffer. If the
  -- underlying primitive is an instance of the class `SafePrimitive`,
  -- please ensure that the contents of the buffer is not modified.
  apply :: g -> BLOCKS (PrimitiveOf g) -> Pointer -> IO ()

  -- | The recommended number of blocks to process at a time. While
  -- processing files, bytestrings it makes sense to handle multiple
  -- blocks at a time. Setting this member appropriately (typically
  -- depends on the cache size of your machine) can drastically
  -- improve cache performance of your program. Default setting is the
  -- number of blocks that fit in @32KB@.
  recommendedBlocks   :: g -> BLOCKS (PrimitiveOf g)
  recommendedBlocks _ = max 1 $ atMost l1Cache

-- | Gives the primitive of a gadget. This function should only be
-- used to satisy types as the actual value returned is `undefined`.
primitiveOf :: Gadget g => g -> PrimitiveOf g
primitiveOf _ = undefined

-- | This function runs an action that expects a gadget as input.
withGadget :: Gadget g
           => Key (PrimitiveOf g)  -- ^ Key to initialise the gadget with.
           -> (g -> IO a)          -- ^ Action to run
           -> IO a
withGadget iv action = withMemory $ withG iv action

-- | Similar to `withGadget` except that the memory allocated for the
-- gadget is a secure memory.
withSecureGadget :: Gadget g
                 => Key (PrimitiveOf g)        -- ^ Key to initialise
                                               -- the gadget with.
                 -> (g -> IO a)                -- ^ Action to run
                 -> IO a
withSecureGadget iv action = withSecureMemory $ withG iv action

withG :: Gadget g
      => Key (PrimitiveOf g)
      -> (g -> IO a)
      -> g
      -> IO a
withG iv action g = initializeMemory g iv >> action g

-- | Like with `withGadget` but returns the result of finalising the
-- gadget rather than the action.  This is useful when the finalised
-- value is what is of interest to us, like for example while
-- computing the cryptographic has of some date.
withGadgetFinalize :: ( Gadget g, FinalizableMemory g)
                   => Key (PrimitiveOf g)
                   -> (g -> IO a)
                   -> IO (FV g)
withGadgetFinalize iv action = withGadget iv
                               $ \ g -> action g >> finalizeMemory g

-- | Similar to `withGadgetFinalize` but the memory used by the gadget
-- is secure.
withSecureGadgetFinalize :: ( Gadget g, FinalizableMemory g)
                         => Key (PrimitiveOf g)
                         -> (g -> IO a)
                         -> IO (FV g)
withSecureGadgetFinalize iv action = withSecureGadget iv
                                     $ \ g -> action g >> finalizeMemory g
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
            -> Pointer   -- ^ the message buffer
            -> IO ()
  unsafePad p bits = unsafeCopyToPointer $ padding p bits

  -- | This counts the number of additional blocks required so that
  -- one can hold the padding. This function is useful if you want to
  -- know the size to be allocated for your message buffers.
  maxAdditionalBlocks :: p -> BLOCKS p


-- | This class captures `Gadget`s which have some padding strategy
-- defined.
class (Gadget g, HasPadding (PrimitiveOf g)) => PaddableGadget g where
  -- | It pads the data with the required padding and processes it. It
  -- expects that enough space is already available for padding. A
  -- default implementation is provided which pads the data and then
  -- calls `apply` of the underlying gadget.
  unsafeApplyLast :: g                      -- ^ Gadget
                  -> BLOCKS (PrimitiveOf g) -- ^ Number of Blocks processed so far
                  -> BYTES Int              -- ^ Bytes to process
                  -> Pointer              -- ^ Location
                  -> IO ()
  unsafeApplyLast g blocks bytes cptr = do
    let bits = inBits bytes :: BITS Word64
        len  = inBits blocks + bits
    unsafePad (primitiveOf g) len (cptr `movePtr` bytes)
    apply g (atMost (bytes + padLength (primitiveOf g) len)) cptr

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


-------------------------- CryptoInverse -------------------------------

-- | This class captures inverse of gadgets. Some primitives have two
-- gadgets associated with it performing works which are inverses of
-- each other. For example, encrypt and decrypt gadgets for the same
-- primitive. This is however not restricted to gadgets which have the same
-- primitives.
class (Gadget g, Gadget (Inverse g)) => CryptoInverse g where
  -- | Inverse of the gadget.
  type Inverse g :: *

-- | Returns inverse of the gadget. Note that this is just used to
-- satisfy types and its value should never be inspected.
inverse :: CryptoInverse g => g -> Inverse g
inverse = undefined

------------------- Type safe lengths in units of block ----------------

-- $typesafelengths$
--
-- When dealing with buffer lengths for a primitive, it is often
-- better to use the type safe units `BLOCKS`. Functions in the raaz
-- package that take lengths usually allow any type safe length as
-- long as they can be converted to bytes. This can avoid a lot of
-- tedious and error prone length calculations.
--

-- | Type safe message length in units of blocks of the primitive.
newtype BLOCKS p = BLOCKS Int
                 deriving (Show, Eq, Ord, Enum, Real, Num, Integral)


instance Primitive p => LengthUnit (BLOCKS p) where
  inBytes p@(BLOCKS x) = scale * blockSize (getPrimitiveType p)
    where scale = BYTES x

getPrimitiveType :: BLOCKS p -> p
getPrimitiveType _ = undefined


-- | The expression @n `blocksOf` p@ specifies the message lengths in
-- units of the block length of the primitive @p@. This expression is
-- sometimes required to make the type checker happy.
blocksOf :: Primitive p =>  Int -> p -> BLOCKS p
blocksOf n _ = BLOCKS n

-------------------- Supported Implementations -------------------------

-- | `HGadget` is pure Haskell gadget implemenation used as the
-- Reference implementation of the `Primitive`. Most of the times it
-- is around 3-4 times slower than `CPortable` version.
newtype HGadget p m = HGadget m

-- | This is the portable C gadget implementation. It is usually
-- recommended over `HGadget` because of being faster than
-- it. However, no architecture specific optimizations are done in
-- this implementation.
newtype CGadget p m = CGadget m

-- | HGadget is an instance of memory.
instance Memory m => Memory (HGadget p m) where
  memoryAlloc = HGadget <$> memoryAlloc
  underlyingPtr (HGadget m) = underlyingPtr m

-- | CGadget is an instance of memory.
instance Memory m => Memory (CGadget p m) where
  memoryAlloc = CGadget <$> memoryAlloc
  underlyingPtr (CGadget m) = underlyingPtr m

{--
-- | If primitive has a name then HGadget has a name
instance HasName p  => HasName (HGadget p m) where
  getName g = "HGadget " ++ getName (getP g)
    where getP :: HGadget p m -> p
          getP _ = undefined

-- | If primitive has a name the CGadget has a name
instance HasName p => HasName (CGadget p m) where
  getName g = "CGadget " ++ getName (getP g)
    where getP :: CGadget p m -> p
          getP _ = undefined

--}
--------------------- Cryptographic operation modes -------------------

-- | A primitive cryptographic operation consists of the following
--
-- * Generation of authenticated signature
--
-- * Verification of the signature against the message
--
-- * Encryption of a message
--
-- * Decryption of an encrypted message
--
-- * Authenticated encryption
--
-- * Decryption of message and verification of its signature
data Mode = SignMode
          | VerifyMode
          | EncryptMode
          | DecryptMode
          | AuthEncryptMode
          | VerifyDecryptMode
          deriving (Show, Eq)

-------------------- Some helper functions -----------------------------

-- | For a block primitive that supports padding, this combinator is
-- used when we care only about the final context and not the contents
-- of the procesed buffer.
transformGadget :: ( ByteSource src
                   , PaddableGadget g
                   )
                => g         -- ^ Gadget
                -> src       -- ^ The byte source
                -> IO ()
{-# INLINEABLE transformGadget #-}
transformGadget g src = allocaBuffer bufSize $ go 0 src
  where nBlocks = recommendedBlocks g
        bufSize = nBlocks + maxAdditionalBlocks p
        p       = primitiveOf g
        go k source cptr =   fill nBlocks source cptr
                             >>= withFillResult continue endIt
           where continue rest = do apply g nBlocks cptr
                                    go (k + nBlocks) rest cptr
                 endIt r       = unsafeApplyLast g k len cptr
                       where len    = inBytes nBlocks - r

-- | A version of `transformContext` which takes a filename instead.
transformGadgetFile :: PaddableGadget g
                    => g          -- ^ Gadget
                    -> FilePath   -- ^ The file name.
                    -> IO ()
transformGadgetFile g fpth = withFile fpth ReadMode $ transformGadget g
{-# INLINEABLE transformGadgetFile #-}
