-- | Module to write stuff to buffers. This writer provides low level
-- writing of data to memory locations given by pointers. It does the
-- necessary pointer arithmetic to make the pointer point to the next
-- location. No range checks are done to speed up the operations and
-- hence these operations are highly unsafe. Use it with care.

{-# LANGUAGE FlexibleContexts #-}
module Raaz.Write
       ( Write, write, writeStorable
       , writeBytes
       , runWrite
       , runWriteForeignPtr
       ) where

import Control.Monad               ( (>=>), void )
import Data.Monoid
import Data.Word                   ( Word8  )
import Foreign.ForeignPtr.Safe     ( withForeignPtr )
import Foreign.Ptr                 ( castPtr )
import Foreign.Storable

import Raaz.Types
import Raaz.Util.Ptr

-- | The write type.
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

-- | Writes a value which is an instance of Storable. This writes the
-- value machine endian. Mostly it is useful in defining the `poke`
-- function in a complicated `Storable` instance.
writeStorable :: Storable a => a -> Write
writeStorable a = Write $ \ cptr -> do
  poke (castPtr cptr) a
  return $ cptr `movePtr` byteSize a

-- | Writes an instance of `CryptoStore`. Endian safety is take into
-- account here. This is what you would need when you write network
-- packets for example. You can also use this to define the `load`
-- function in a compicated `CryptoStore` instance.
write :: CryptoStore a => a -> Write
write a = Write $ \ cptr -> do
  store cptr a
  return $ cptr `movePtr` byteSize a

-- | The combinator @writeBytes n b@ writes @b@ as the next @n@
-- consecutive bytes.
writeBytes :: CryptoCoerce n (BYTES Int) => n -> Word8 -> Write
writeBytes n b = Write $ \ cptr ->
  memset cptr b bytes
  >> return (cptr `movePtr` n)
  where bytes = cryptoCoerce n :: BYTES Int
