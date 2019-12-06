{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE KindSignatures   #-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE MonoLocalBinds   #-}
module Buffer
       ( allocBufferFor
       , BufferPtr
       , Buffer, getBufferPointer, bufferSize
       ) where

import GHC.TypeLits

import Raaz.Core

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

instance KnownNat n => Memory (Buffer n) where
  memoryAlloc = allocThisBuffer
    where allocThisBuffer = Buffer <$> pointerAlloc sz
          bufferProxy     :: Alloc (Buffer n) -> Proxy (Buffer n)
          bufferProxy _   = Proxy
          algn            = ptrAlignment (Proxy :: Proxy BufferPtr)
          sz              = atLeastAligned (actualBufferSize $ bufferProxy allocThisBuffer) algn

  unsafeToPointer = unBuffer

allocBufferFor :: MonadIOCont m
               => BLOCKS Prim
               -> (BufferPtr  -> m a) -> m a

allocBufferFor blks = allocaAligned totalSize
  where totalSize = blks `mappend` additionalBlocks
