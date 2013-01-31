{-|

Generic cryptographic algorithms.

-}

{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE MultiParamTypeClasses       #-}
{-# LANGUAGE GeneralizedNewtypeDeriving  #-}
module Raaz.Primitives
       ( BlockPrimitive(..)
       , HasPadding(..)
       , BLOCKS, blocksOf
       ) where

import           Control.Applicative((<$>))
import           Control.Monad(foldM)
import qualified Data.ByteString      as B
import           Data.ByteString.Internal(unsafeCreate)
import qualified Data.ByteString.Lazy as L
import           Data.Word(Word64)
import           Foreign.Ptr(castPtr)
import           System.IO(Handle, withFile, IOMode(ReadMode))

import Raaz.Types
import Raaz.Util.ByteString(fillUpChunks, fillUp, unsafeCopyToCryptoPtr)
import Raaz.Util.Ptr

-- | Type safe message length in units of blocks of the primitive.
newtype BLOCKS p = BLOCKS Int
                 deriving (Show, Eq, Ord, Enum, Real, Num, Integral)

-- | Abstraction that captures crypto primitives that work one block
-- at a time. Block primitives process data one block at a
-- time. Examples are block ciphers, Merkle-Damgård hashes etc. The
-- minimal complete definition consists of `blockSize`, the associated
-- type `Cxt` and one of `process` or `processSingle`.
class BlockPrimitive p where

  blockSize :: p -> BYTES Int -- ^ Block size

  -- | Block primitives require carrying around a context to process
  -- subsequent blocks. This associated type captures such a context.
  data Cxt p

  -- | This `process` function is what does all the hardwork of the
  -- primitive. A default implementation in terms of `processSingle`,
  -- but you can provide a more efficient implementation. Whether the
  -- data in the message buffer is left intact or not, depends on the
  -- primitive.
  process :: Cxt p     -- ^ The context passed from the previous block
          -> BLOCKS p  -- ^ The number of blocks of data.
          -> CryptoPtr -- ^ The message buffer
          -> IO (Cxt p)

  process cxt b cptr = fst <$> foldM moveAndHash (cxt,cptr) [1..b]
    where
      getCxt :: Cxt p -> p
      getCxt _  = undefined
      sz        = blockSize $ getCxt cxt
      moveAndHash (context,ptr) _ = do newCxt <- processSingle context ptr
                                       return (newCxt, ptr `movePtr` sz)

  -- | Reads one block from the CryptoPtr and produces the next
  -- context from the previous context. There is a default
  -- implementation in terms of `process`. However, for efficiency you
  -- might consider defining a separte version.
  processSingle :: Cxt p         -- ^ The context
                -> CryptoPtr     -- ^ The message buffer
                -> IO (Cxt p)
  processSingle cxt cptr = process cxt 1 cptr

  -- | The recommended number of blocks to process at a time. While
  -- processing files, bytestrings it makes sense to handle multiple
  -- blocks at a time. Setting this member appropriately (typically
  -- depends on the cache size of your machine) can drastically
  -- improve cache performance of your program. Default setting is the
  -- number of blocks that fit in @32KB@.
  recommendedBlocks   :: p -> BLOCKS p
  recommendedBlocks _ = cryptoCoerce (1024 * 32 :: BYTES Int)

instance ( BlockPrimitive p
         , Num by
         ) => CryptoCoerce (BLOCKS p) (BYTES by) where
  cryptoCoerce b@(BLOCKS n) = fromIntegral $ blockSize (prim b) *
                                           fromIntegral n
         where prim :: BLOCKS p -> p
               prim _ = undefined
  {-# INLINE cryptoCoerce #-}


instance ( BlockPrimitive p
         , Num bits
         ) => CryptoCoerce (BLOCKS p) (BITS bits) where
  cryptoCoerce b@(BLOCKS n) = fromIntegral $ 8 * blockSize (prim b) *
                                           fromIntegral n
         where prim :: BLOCKS p -> p
               prim _ = undefined
  {-# INLINE cryptoCoerce #-}

-- | BEWARE: There can be rounding errors if the number of bytes is
-- not a multiple of block length.
instance ( BlockPrimitive p
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
instance ( BlockPrimitive p
         , Integral by
         ) => CryptoCoerce (BITS by) (BLOCKS p) where
  cryptoCoerce = cryptoCoerce . bytes
    where bytes :: Integral by => BITS by -> BYTES by
          bytes = cryptoCoerce
  {-# INLINE cryptoCoerce #-}
-- | The expression @n `blocksOf` p@ specifies the message lengths in
-- units of the block length of the primitive @p@. This expression is
-- sometimes required to make the type checker happy.
blocksOf :: BlockPrimitive p =>  Int -> p -> BLOCKS p
blocksOf n _ = BLOCKS n

-- | This class captures a block primitive that has a length dependent
-- padding strategy. The obvious reason for padding is to handle
-- messages that are not multiples of the block size. However, there
-- is a more subtle reason. For certain hashing schemes like
-- Merkel-Damgård, the strength of the hash crucially depends on the
-- padding. The minmal complete definition for this class is
-- `padLength`, `maxAdditionalBlocks` and one of `padding` or
-- `unsafePad`.
class BlockPrimitive p => HasPadding p where
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
