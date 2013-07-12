{-|

Generic cryptographic algorithms.

-}

{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE MultiParamTypeClasses       #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
{-# LANGUAGE FlexibleContexts            #-}

module Raaz.Primitives
       ( Primitive(..)
       , Implementation(..)
       , CryptoPrimitive(..)
       , HasPadding(..)
       , BLOCKS, blocksOf
       , transformContext, transformContextFile
       ) where

import           Control.Applicative((<$>))
import           Control.Monad(foldM)
import qualified Data.ByteString      as B
import           Data.ByteString.Internal(unsafeCreate)
import           Data.Word(Word64)
import           Foreign.Ptr(castPtr)
import           System.IO(withFile, IOMode(ReadMode))

import Raaz.Types
import Raaz.ByteSource
import Raaz.Util.ByteString
import Raaz.Util.Ptr

----------------------- A primitive ------------------------------------

-- | Abstraction that captures crypto primitives that work one block
-- at a time.  Primitives process data one block at a time. Examples
-- are block ciphers, Merkle-Damgård hashes etc. Stream primitives may
-- be captured as primitives with block size 1.
class Primitive p where

  blockSize :: p -> BYTES Int -- ^ Block size

-------------------- Implementation  -----------------------------------

-- | The raaz library supports multiple implementation of the same
-- primitives. This class captures an implementation.
--
class Primitive (PrimitiveOf i) => Implementation i where

  -- | The primitive associated with this implementation
  type PrimitiveOf i :: *

  -- | Block primitives require carrying around a context to process
  -- subsequent blocks. This associated type captures such a context.
  data Cxt i

  -- | This `process` function is what does all the hardwork of the
  -- primitive. A default implementation in terms of `processSingle`,
  -- but you can provide a more efficient implementation. Whether the
  -- data in the message buffer is left intact or not, depends on the
  -- primitive.
  process :: Cxt i                 -- ^ The context passed from the
                                   -- previous block
          -> BLOCKS (PrimitiveOf i)  -- ^ The number of blocks of data.
          -> CryptoPtr             -- ^ The message buffer
          -> IO (Cxt i)
  process cxt b cptr = fst <$> foldM moveAndHash (cxt,cptr) [1..b]
    where
      getCxt :: Cxt i -> PrimitiveOf i
      getCxt _  = undefined
      sz        = blockSize $ getCxt cxt
      moveAndHash (context,ptr) _ = do newCxt <- processSingle context ptr
                                       return (newCxt, ptr `movePtr` sz)

  -- | Reads one block from the CryptoPtr and produces the next
  -- context from the previous context. There is a default
  -- implementation in terms of `process`. However, for efficiency you
  -- might consider defining a separte version.
  processSingle :: Cxt i         -- ^ The context
                -> CryptoPtr     -- ^ The message buffer
                -> IO (Cxt i)
  processSingle cxt cptr = process cxt 1 cptr

  -- | The recommended number of blocks to process at a time. While
  -- processing files, bytestrings it makes sense to handle multiple
  -- blocks at a time. Setting this member appropriately (typically
  -- depends on the cache size of your machine) can drastically
  -- improve cache performance of your program. Default setting is the
  -- number of blocks that fit in @32KB@.
  recommendedBlocks   :: i -> BLOCKS (PrimitiveOf i)
  recommendedBlocks _ = cryptoCoerce (1024 * 32 :: BYTES Int)

---------------------- A crypto primitive ------------------------------

-- | A crypto primitive is a primitive together with a recommended
-- implementation.
class ( Implementation  (Recommended p)
      , p ~ PrimitiveOf (Recommended p)
      ) => CryptoPrimitive p where
  type Recommended p :: *

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

class HasPadding p where

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
transformContext  :: ( ByteSource src
                     , Implementation i
                     , HasPadding (PrimitiveOf i)
                     )
                  => Cxt i     -- ^ The starting context
                  -> src       -- ^ The byte source
                  -> IO (Cxt i)
{-# INLINEABLE transformContext #-}

transformContext cxt src = allocaBuffer bufSize $ go 0 cxt src
  where nBlocks = recommendedBlocks $ getImplementation cxt
        bufSize = nBlocks + maxAdditionalBlocks p
        p       = getPrimitive cxt

        getImplementation :: Implementation i => Cxt i -> i
        getImplementation _ = undefined
        getPrimitive :: Implementation i => Cxt i -> PrimitiveOf i
        getPrimitive _ = undefined

        go k context source cptr =   fill nBlocks source cptr
                                 >>= withFillResult continue endIt
           where continue rest = do context' <- process context nBlocks cptr
                                    go (k + nBlocks) context' rest cptr
                 endIt r       = do unsafePad p bits padPtr
                                    process context blks cptr
                       where len    = cryptoCoerce nBlocks - r
                             bits   = cryptoCoerce k + cryptoCoerce len
                             padPtr = cptr `movePtr` len
                             blks   = cryptoCoerce $ len + padLength p bits

-- | A version of `transformContext` which takes a filename instead.
transformContextFile ::( Implementation i
                       , HasPadding (PrimitiveOf i)
                       )
                     => Cxt i      -- ^ The starting context
                     -> FilePath   -- ^ The file name.
                     -> IO (Cxt i)
transformContextFile cxt fpth = withFile fpth ReadMode $ transformContext cxt
