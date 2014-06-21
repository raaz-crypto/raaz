-- | Module to write stuff to buffers. This writer provides low level
-- writing of data to memory locations given by pointers. It does the
-- necessary pointer arithmetic to make the pointer point to the next
-- location. No range checks are done to speed up the operations and
-- hence these operations are highly unsafe. If you want proper range
-- checks please use "Raaz.Core.Write" instead.
--
-- An important use case for these unsafe functions is in the
-- definition of `Storable` and `EndianStore` instances of complicated
-- data types.


{-# LANGUAGE FlexibleContexts #-}
module Raaz.Core.Write.Unsafe
       ( Write, write, writeStorable
       , writeBytes, writeByteString
       , runWrite
       , runWriteForeignPtr
       ) where

import Control.Monad           ( (>=>), void )
import Data.ByteString         ( ByteString )
import Data.Monoid
import Data.Word               ( Word8  )
import Foreign.ForeignPtr.Safe ( withForeignPtr )
import Foreign.Ptr             ( castPtr )
import Foreign.Storable

import Raaz.Core.Types
import Raaz.Core.Util.Ptr
import Raaz.Core.Util.ByteString    as BU

-- | A write is an action which when executed using `runWrite` writes
-- bytes to the input buffer. The action takes care of updating the
-- pointer location but nothing more is done. In particular, it is the
-- responsibility of the programmer to make sure that there is enough
-- space in the buffer for the data. `Write`s are monoid and hence can
-- be concatnated using the `<>` operator.
newtype Write = Write (CryptoPtr -> IO CryptoPtr)

instance Monoid Write where
  mempty                               = Write return
  mappend (Write first) (Write second) = Write (first >=> second)

-- | Perform a write action on a buffer pointed by the crypto pointer.
runWrite :: CryptoPtr -> Write -> IO ()
runWrite cptr (Write action) = void $ action cptr

-- | Perform a write action on a buffer pointed by a foreign pointer
runWriteForeignPtr   :: ForeignCryptoPtr -> Write -> IO ()
runWriteForeignPtr fptr (Write action) = void $ withForeignPtr fptr action

-- | Perform the action on the crypto pointer and move the pointer by
-- the given length.
writeAndMove :: LengthUnit l
             => (CryptoPtr -> IO a)
             -> l
             -> Write
writeAndMove action l = Write $ \ cptr -> do
  void   $ action cptr
  return $ cptr `movePtr` l


-- | Writes a value which is an instance of Storable. This writes the
-- value in the machine endian. A common use case for this function is
-- in defining the `poke` function for a complicated `Storable`
-- instance.
writeStorable :: Storable a => a -> Write
writeStorable a = pokeIt `writeAndMove` byteSize a
  where pokeIt cptr = poke (castPtr cptr) a

-- | Writes an instance of `EndianStore`. Endian safety is take into
-- account here. This is what you would need when you write network
-- packets for example. You can also use this to define the `store`
-- function in a complicated `EndianStore` instance.
write :: EndianStore a => a -> Write
write a = flip store a `writeAndMove` byteSize a

-- | The combinator @writeBytes b n@ writes @b@ as the next @n@
-- consecutive bytes. Here @n@ can be any type safe length unit.
writeBytes :: LengthUnit n => Word8 -> n -> Write
writeBytes w8 n = memsetIt `writeAndMove` n
  where memsetIt cptr = memset cptr w8 n

-- | Writes a strict `ByteString`.
writeByteString :: ByteString -> Write
writeByteString bs = BU.unsafeCopyToCryptoPtr bs `writeAndMove`
                     BU.length bs
