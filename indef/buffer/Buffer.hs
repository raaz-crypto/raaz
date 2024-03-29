{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE KindSignatures   #-}
{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE MonoLocalBinds   #-}
module Buffer
       ( BufferPtr
       , Buffer
       , withBufferPtr
       , unsafeWithBufferPtr
       , memsetBuffer
       -- ** Some unsafe functions
       , unsafeGetBufferPointer
       , bufferSize
       ) where

import GHC.TypeLits

import Raaz.Core
import Raaz.Core.Memory (Access(..))
import Implementation

-- | A buffer @buf :: Buffer n@ is a memory element that has enough
-- space for the @n@ blocks of the primitive and, if required by the
-- implementation, any additional blocks that might be used for
-- padding of the last chunk of message.
newtype Buffer (n :: Nat) = Buffer { unBuffer :: Ptr Word8 }

-- | Get the underlying pointer for the buffer.
unsafeGetBufferPointer :: Buffer n -> BufferPtr
unsafeGetBufferPointer = unsafeAlign . castPointer . unBuffer

-- | Get the buffer alignment.
bufferAlignment :: KnownNat n => Proxy (Buffer n) -> Alignment
bufferAlignment = ptrAlignment . fmap unsafeGetBufferPointer

-- | This takes a buffer pointer action and runs it with the underlying pointer associated with
-- the buffer. The action is supposed to use
unsafeWithBufferPtr :: KnownNat n
                    => (BufferPtr -> a)
                    -> Buffer n
                    -> a
unsafeWithBufferPtr action = action . unsafeGetBufferPointer

-- | Run the action on the buffer pointer.
withBufferPtr :: KnownNat n
              => (BufferPtr -> BlockCount Prim -> a)
              -> Buffer n
              -> a
withBufferPtr action buf = unsafeWithBufferPtr act buf
  where act = flip action $ bufferSize $ pure buf

-- | Memset the given buffer.
memsetBuffer :: KnownNat n => Word8 -> Buffer n -> IO ()
memsetBuffer = withBufferPtr . flip memset


{-# INLINE bufferSize #-}
-- | The size of data (measured in blocks) that can be safely
-- processed inside this buffer.
bufferSize :: KnownNat n => Proxy (Buffer n) -> BlockCount Prim
bufferSize = flip blocksOf Proxy . fromIntegral . natVal . nProxy
  where nProxy :: Proxy (Buffer n) -> Proxy n
        nProxy  _ = Proxy

-- WARNING: Internal function that should not be exposed. Not to be
-- exposed else can be confusing with `bufferSize`. Even if we want to
-- process n blocks, we need to account for the additional Blocks that
-- is needed by the implementation. This is therefore the needed size
-- in blocks.
actualBufferSize :: KnownNat n => Proxy (Buffer n) -> BlockCount Prim
actualBufferSize bproxy = bufferSize bproxy <> additionalBlocks


-- WARNING: Internal function that should not be exposed from this
-- module.  Not to be confused with `bufferSize` and
-- `actualBufferSize`. In addition to the blocks we might need to
-- account for the alignment requirement of the implementation when
-- allocating.
allocBufferSize :: KnownNat n => Proxy (Buffer n) -> BYTES Int
allocBufferSize prxy = atLeastAligned (actualBufferSize prxy) $ bufferAlignment prxy


instance KnownNat n => Memory (Buffer n) where
  memoryAlloc = allocThisBuffer
    where allocThisBuffer = Buffer <$> pointerAlloc sz
          sz              = allocBufferSize $ bufferProxy allocThisBuffer
          bufferProxy     :: Alloc (Buffer n) -> Proxy (Buffer n)
          bufferProxy _   = Proxy

  unsafeToPointer = unBuffer


instance KnownNat n => ReadAccessible (Buffer n) where
  readAccess buf = unsafeWithPointerCast makeAccess $ unsafeGetBufferPointer buf
    where makeAccess bptr = [ Access bptr $ inBytes $ bufferSize $ pure buf ]


  beforeReadAdjustment buf = unsafeWithPointer (adjust (Proxy :: Proxy Prim) nelems)
                                 $ unsafeGetBufferPointer buf
    where getProxy :: Buffer n -> Proxy n
          getProxy _ = Proxy
          nelems     = fromEnum $ natVal $ getProxy buf
          adjust     :: Primitive prim => Proxy prim -> Int -> BlockPtr prim  -> IO ()
          adjust _ n ptr  = adjustEndian ptr n


instance KnownNat n => WriteAccessible (Buffer n) where
  writeAccess = readAccess
  afterWriteAdjustment = beforeReadAdjustment
