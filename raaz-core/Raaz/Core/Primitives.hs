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

         Primitive(..), Gadget(..)
       , newGadget, newInitializedGadget, initialize, finalize
       , primitiveOf, withGadget
       , PaddableGadget(..)
       , CGadget(..), HGadget(..)
       , SafePrimitive
       , HasPadding(..)
       , CryptoPrimitive(..)
       , BLOCKS, blocksOf
       , transformGadget, transformGadgetFile
       , CryptoInverse(..), inverse
         -- * Cryptographic operation modes
#if UseKinds
       , Mode(..)
#else
       , SignMode(..)
       , VerifyMode(..)
       , EncryptMode(..)
       , DecryptMode(..)
       , AuthEncryptMode(..)
       , VerifyDecryptMode(..)
#endif
       ) where

import qualified Data.ByteString          as B
import           Data.ByteString.Internal (unsafeCreate)
import           Data.Word                (Word64)
import           Foreign.Ptr              (castPtr)
import           System.IO                (withFile, IOMode(ReadMode))

import           Raaz.Core.ByteSource
import           Raaz.Core.HasName
import           Raaz.Core.Memory
import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString
import           Raaz.Core.Util.Ptr
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

  -- | Key used to initializa the gadget
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
-- respectively). Gadgets are stateful and the state is typically
-- stored inside the memory of the gadgets captured by the associated
-- type MemoryOf g
--
-- Gadget instances where the underlying primitive is an instance of
-- `SafePrimitive` should ensure that the input buffer is not
-- modified.

class ( Primitive (PrimitiveOf g)
      , Memory (MemoryOf g)
      , InitializableMemory (MemoryOf g)
      , Key (PrimitiveOf g) ~ IV (MemoryOf g)
      ) => Gadget g where

  -- | The primitive for which this is a gadget
  type PrimitiveOf g

  -- | The (type of the) internal memory used by the gadget.
  type MemoryOf g

  -- | The action @newGadgetWithMemory mem@ creates a gadget which
  -- uses @mem@ as its internal memory. If you want the internal data
  -- to be protected from being swapped out (for example if the
  -- internal memory contains sensitive data) then pass a secured
  -- memory to this function.
  newGadgetWithMemory :: MemoryOf g -> IO g

  -- | Returns the memory of the gadget. This is used while
  -- initializing and finalizing the memory.
  getMemory :: g -> MemoryOf g

  -- | The recommended number of blocks to process at a time. While
  -- processing files, bytestrings it makes sense to handle multiple
  -- blocks at a time. Setting this member appropriately (typically
  -- depends on the cache size of your machine) can drastically
  -- improve cache performance of your program. Default setting is the
  -- number of blocks that fit in @32KB@.
  recommendedBlocks   :: g -> BLOCKS (PrimitiveOf g)
  recommendedBlocks _ = max 1 $ atMost l1Cache

  -- | This function actually applies the gadget on the buffer. If the
  -- underlying primitive is an instance of the class `SafePrimitive`,
  -- please ensure that the contents of the buffer are not modified.
  apply :: g -> BLOCKS (PrimitiveOf g) -> CryptoPtr -> IO ()


-- | The function @newInitializedGadget iv@ creates a new instance of
-- the gadget with its memory allocated and initialised to @iv@.
newInitializedGadget :: Gadget g => IV (MemoryOf g) -> IO g
newInitializedGadget iv = do
  g <- newGadget
  initialize g iv
  return g

-- | The function @newGadget@ creates a new instance of the gadget
-- with its memory allocated.
newGadget :: Gadget g => IO g
newGadget = newMemory >>= newGadgetWithMemory

-- | Initialize the gadgets memory.
initialize :: Gadget g => g -> IV (MemoryOf g) -> IO ()
initialize = initializeMemory . getMemory

-- | Finalise the gadgets memory.
finalize :: ( Gadget g
            , FinalizableMemory (MemoryOf g)
            ) => g -> IO (FV (MemoryOf g))
finalize = finalizeMemory . getMemory

-- | Gives the primitive of a gadget. This function should only be
-- used to satisy types as the actual value returned is `undefined`.
primitiveOf :: Gadget g => g -> PrimitiveOf g
primitiveOf _ = undefined

-- | This function runs an action that expects a gadget as input.
withGadget :: Gadget g
           => IV (MemoryOf g) -- ^ IV to initialize the gadget with.
           -> (g -> IO a)     -- ^ Action to run
           -> IO a
withGadget iv action = newInitializedGadget iv >>= action

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
                  -> CryptoPtr              -- ^ Location
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
newtype HGadget p = HGadget (MemoryOf (HGadget p))

-- | This is the portable C gadget implementation. It is usually
-- recommended over `HGadget` because of being faster than
-- it. However, no architecture specific optimizations are done in
-- this implementation.
newtype CGadget p = CGadget (MemoryOf (CGadget p))

-- | If primitive has a name then HGadget has a name
instance HasName p => HasName (HGadget p) where
  getName g = "HGadget " ++ getName (getP g)
    where getP :: HGadget p -> p
          getP _ = undefined

-- | If primitive has a name the CGadget has a name
instance HasName p => HasName (CGadget p) where
  getName g = "CGadget " ++ getName (getP g)
    where getP :: CGadget p -> p
          getP _ = undefined


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
#if UseKinds
data Mode = SignMode
          | VerifyMode
          | EncryptMode
          | DecryptMode
          | AuthEncryptMode
          | VerifyDecryptMode
          deriving (Show, Eq)
#else
data SignMode = SignMode deriving (Show, Eq)

data VerifyMode = VerifyMode deriving (Show, Eq)

data EncryptMode = EncryptMode deriving (Show, Eq)

data DecryptMode = DecryptMode deriving (Show, Eq)

data AuthEncryptMode = AuthEncryptMode deriving (Show, Eq)

data VerifyDecryptMode = VerifyDecryptMode deriving (Show, Eq)

{-# DEPRECATED SignMode, VerifyMode, EncryptMode, DecryptMode,
   AuthEncryptMode, VerifyDecryptMode
   "Will be changed to Data Constructor of type Mode from ghc7.6 onwards" #-}
#endif

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
