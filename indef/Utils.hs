{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE KindSignatures   #-}
{-# LANGUAGE DataKinds        #-}
module Utils
       ( allocBufferFor
       , processByteSource
       , transform
       , BufferPtr
       , Buffer, getBufferPointer, bufferSize, processBuffer
       ) where

import Control.Monad.IO.Class          (liftIO)
import Data.ByteString          as B
import Data.ByteString.Internal as IB
import Data.Proxy
import Data.Monoid
import Foreign.Ptr                     (castPtr)
import GHC.TypeLits

import Raaz.Core
import Raaz.Core.Types.Internal

import Implementation

-- | The pointer type associated with the buffer used by the
-- implementation.
type BufferPtr = AlignedPointer BufferAlignment

-- | A memory buffer than can handle up to @n@ blocks of data. This
-- happens when you need to do some transformation on internal data
-- using a primitive. An example is using a stream cipher for
-- pseudo-random generation. Note that and additional blocks that
-- might be required at the end for padding is taken care of and one
-- does not need to worry about it here. I.e. @Buffer n@ has enough
-- space for the @n@ blocks and if required any additional blocks that
-- meant for padding.
newtype Buffer (n :: Nat) = Buffer { unBuffer :: Pointer }

-- | Get the underlying pointer for the buffer.
getBufferPointer :: Buffer n -> BufferPtr
getBufferPointer = nextAlignedPtr . unBuffer

{-# INLINE bufferSize #-}
-- | The size of data (measured in blocks) that can be safely
-- processed inside this buffer.
bufferSize :: KnownNat n => Proxy (Buffer n) -> BLOCKS Prim
bufferSize = flip blocksOf Proxy . fromIntegral . natVal . nProxy
  where nProxy :: Proxy (Buffer n) -> Proxy n
        nProxy  _ = Proxy

-- | Internal function used by allocation.  WARNING: Not to be exposed
-- else can be confusing with `bufferSize`.
actualBufferSize :: KnownNat n => Proxy (Buffer n) -> BLOCKS Prim
actualBufferSize bproxy = bufferSize bproxy <> additionalBlocks


-- | Process the data in the buffer.
{-# INLINE processBuffer #-}
processBuffer :: KnownNat n => Buffer n -> MT Internals ()
processBuffer buf = processBlocks (getBufferPointer buf) $ bufferSize $ pure buf

instance KnownNat n => Memory (Buffer n) where
  memoryAlloc = allocThisBuffer
    where allocThisBuffer = Buffer <$> pointerAlloc sz
          bufferProxy     :: Alloc (Buffer n) -> Proxy (Buffer n)
          bufferProxy _   = Proxy
          algn            = ptrAlignment (Proxy :: Proxy BufferPtr)
          sz              = atLeastAligned (actualBufferSize $ bufferProxy allocThisBuffer) algn

  unsafeToPointer = unBuffer

-- | Allocate a buffer for a primitive.
allocBufferFor :: (KnownNat BufferAlignment, MonadIOCont m)
               => BLOCKS Prim
               -> (BufferPtr  -> m a) -> m a
allocBufferFor blks = allocaAligned totalSize
  where totalSize = blks `mappend` additionalBlocks

-- | Process a byte source.
processByteSource :: (KnownNat BufferAlignment, ByteSource src) => src -> MT Internals ()
processByteSource src = allocBufferFor blks $ \ ptr -> do
  processChunks (processBlocks ptr blks) (processLast ptr) src blks (forgetAlignment ptr)
  where blks       = atLeast l1Cache :: BLOCKS Prim


{-
-- | Compute the digest of a message.
computeDigest :: ( ByteSource src
                 , KnownNat BufferAlignment
                 , Initialisable Internals (Key Prim)
                 , Extractable   Internals Prim
                 )
              => Key Prim -> src -> IO Prim
computeDigest key src = insecurely $ do initialise key
                                        processByteSource src
                                        extract
-}

transform :: ByteString -> MT Internals ByteString
transform bs = allocBufferFor bufSz $ \ buf ->  do
  let bufPtr = forgetAlignment buf
    in do liftIO $ unsafeCopyToPointer bs bufPtr -- Copy the input to buffer.
          processLast buf strSz
          str  <- liftIO $ IB.create sbytes
                  $ \ ptr -> Raaz.Core.memcpy (destination (castPtr ptr)) (source bufPtr) strSz
          return str

  where strSz           = Raaz.Core.length bs
        BYTES sbytes    = strSz
        --
        -- Buffer size is at least the size of the input.
        --
        bufSz           = atLeast strSz `mappend` additionalBlocks
{-        

-- | Transform a given bytestring using the recommended implementation
-- of a stream cipher.
transformAndDigest :: ( KnownNat BufferAlignment
                      , Initialisable Internals (Key Prim)
                      , Extractable   Internals (Digest Prim)
                      )
                   => Key Prim
                   -> ByteString
                   -> (ByteString, Digest Prim)
                   
-- | Transform a given bytestring using the recommended implementation
-- of a stream cipher.
transformAndDigest :: ( KnownNat BufferAlignment
                      , Initialisable Internals (Key Prim)
                      , Extractable   Internals (Digest Prim)
                      )
                   => Key Prim
                   -> ByteString
                   -> (ByteString, Digest Prim)

transformAndDigest key bs = unsafePerformIO $ insecurely go
-}
