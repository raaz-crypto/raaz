{-|

This module contains low level function to manipulate pointers and
allocate/free memory. The size and offset types here are more friendly
to use with type safe lengths.

-}

{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
module Raaz.Util.Ptr
       ( byteSize
       , allocaBuffer, mallocBuffer
       , movePtr
       , storeAt, storeAtIndex
       , loadFrom, loadFromIndex
       , hFillBuf
       , memset, memmove, memcpy
       ) where

import Data.Word             (Word8)
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Storable      (Storable, sizeOf)
import System.IO             (hGetBuf, Handle)
import Raaz.Types

-- | Similar to `sizeOf` but returns the length in type safe units.
byteSize :: Storable a => a -> BYTES Int
{-# INLINE byteSize #-}
byteSize = BYTES . sizeOf

-- | The expression @allocaBuffer l action@ allocates a local buffer
-- of length @l@ and passes it on to the IO action @action@. No
-- explicit freeing of the memory is required as the memory is
-- allocated locally and freed once the action finishes. It is better
-- to use this function than @`allocaBytes`@ as it does type safe
-- scaling.
allocaBuffer :: CryptoCoerce l (BYTES Int)
             => l                    -- ^ buffer length
             -> (CryptoPtr -> IO b)  -- ^ the action to run
             -> IO b
{-# INLINE allocaBuffer #-}
allocaBuffer l = allocaBytes bytes
  where BYTES bytes = cryptoCoerce l

-- | Creates a memory of given size. It is better to use over
-- @`mallocBytes`@ as it uses typesafe length.
mallocBuffer :: CryptoCoerce l (BYTES Int)
             => l                    -- ^ buffer length
             -> IO CryptoPtr
{-# INLINE mallocBuffer #-}
mallocBuffer l = mallocBytes bytes
  where BYTES bytes = cryptoCoerce l

-- | Moves a pointer by a specified offset. The offset can be of any
-- type that supports coercion to @`BYTES` Int@. It is safer to use
-- this function than @`plusPtr`@, as it does type safe scaling.
movePtr :: CryptoCoerce offset (BYTES Int)
        => CryptoPtr
        -> offset
        -> CryptoPtr
{-# INLINE movePtr #-}
movePtr cptr offset = cptr `plusPtr` bytes
  where BYTES bytes = cryptoCoerce offset



-- | Store the given value as the @n@-th element of the array
-- pointed by the crypto pointer.
storeAtIndex :: CryptoStore w
             => CryptoPtr -- ^ the pointer to the first element of the
                          -- array
             -> Int       -- ^ the index of the array
             -> w         -- ^ the value to store
             -> IO ()
{-# INLINE storeAtIndex #-}
storeAtIndex cptr index w = storeAt cptr offset w
  where offset = toEnum index * byteSize w

-- | Store the given value at an offset from the crypto pointer. The
-- offset is given in type safe units.
storeAt :: ( CryptoStore w
           , CryptoCoerce offset (BYTES Int)
           )
        => CryptoPtr   -- ^ the pointer
        -> offset      -- ^ the absolute offset in type safe length units.
        -> w           -- ^ value to store
        -> IO ()
{-# INLINE storeAt #-}
storeAt cptr offset = store $ cptr `movePtr` offset

-- | Load the @n@-th value of an array pointed by the crypto pointer.
loadFromIndex :: CryptoStore w
              => CryptoPtr -- ^ the pointer to the first element of
                           -- the array
              -> Int       -- ^ the index of the array
              -> IO w
{-# INLINE loadFromIndex #-}
loadFromIndex cptr index = loadP undefined
   where loadP ::  (CryptoStore w, Storable w) => w -> IO w
         loadP w = loadFrom cptr offset
           where offset = toEnum index * byteSize w

-- | Load from a given offset. The offset is given in type safe units.
loadFrom :: ( CryptoStore w
            , CryptoCoerce offset (BYTES Int)
            )
         => CryptoPtr -- ^ the pointer
         -> offset    -- ^ the offset
         -> IO w
{-# INLINE loadFrom #-}
loadFrom cptr offset = load $ cptr `movePtr` offset

-- | A version of `hGetBuf` which works for any type safe length units.
hFillBuf :: (CryptoCoerce bufSize (BYTES Int))
         => Handle
         -> CryptoPtr
         -> bufSize
         -> IO (BYTES Int)
{-# INLINE hFillBuf #-}
hFillBuf handle cptr sz = fmap BYTES $ hGetBuf handle cptr bytes
     where BYTES bytes = cryptoCoerce sz

-- | Some common PTR functions abstracted over type safe length.
foreign import ccall unsafe "string.h memcpy" c_memcpy
    :: CryptoPtr -> CryptoPtr -> BYTES Int -> IO (CryptoPtr)

-- | Copy between pointers.
memcpy :: CryptoCoerce l (BYTES Int)
       => CryptoPtr -- ^ Dest
       -> CryptoPtr -- ^ Src
       -> l         -- ^ Number of Bytes to copy
       -> IO ()
memcpy p q l = c_memcpy p q (cryptoCoerce l) >> return ()

foreign import ccall unsafe "string.h memmove" c_memmove
    :: CryptoPtr -> CryptoPtr -> BYTES Int -> IO (CryptoPtr)

-- | Move between pointers.
memmove :: CryptoCoerce l (BYTES Int)
        => CryptoPtr -- ^ Dest
        -> CryptoPtr -- ^ Src
        -> l         -- ^ Number of Bytes to copy
        -> IO ()
memmove p q l = c_memmove p q (cryptoCoerce l) >> return ()


foreign import ccall unsafe "string.h memset" c_memset
    :: CryptoPtr -> Word8 -> BYTES Int -> IO CryptoPtr

-- | Sets the given number of Bytes to the specified value.
memset :: CryptoCoerce l (BYTES Int)
       => CryptoPtr -- ^ Target
       -> Word8     -- ^ Value byte to set
       -> l         -- ^ Number of bytes to set
       -> IO ()
memset p w l = c_memset p w (cryptoCoerce l) >> return ()
