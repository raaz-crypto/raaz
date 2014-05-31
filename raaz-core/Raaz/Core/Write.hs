-- | Module to write stuff to buffers. As opposed to similar functions
-- exposed in "Raaz.Core.Write.Unsafe", the writes exposed here are
-- safe as necessary range checks are done on the buffer before
-- writing stuff to it.

{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Core.Write
       ( Write, runWrite, tryWrite
       , write, writeStorable
       , WriteException(..)
       , writeBytes, writeByteString

       ) where

import           Control.Exception
import           Data.ByteString      (ByteString)
import           Data.Monoid
import           Data.Typeable
import           Data.Word            (Word8)
import           Foreign.Storable

import           Raaz.Core.Types
import           Raaz.Core.Util.Ptr
import           Raaz.Core.Util.ByteString as BU

import qualified Raaz.Core.Write.Unsafe    as WU

-- | A write is an action which when executed using `runWrite` writes
-- bytes to the input buffer. It is similar to the `WU.Write` type
-- exposed from the "Raaz.Write.Unsafe" module except that it keeps
-- track of the total bytes that would be written to the buffer if the
-- action is run. The `runWrite` action will raise an error if the
-- buffer it is provided with is of size smaller. `Write`s are monoid
-- and hence can be concatnated using the `<>` operator.
newtype Write = Write (Sum (BYTES Int), WU.Write)
              deriving Monoid

-- | The type of the exception raised when there is an overflow of the
-- cryptobuffer.
data WriteException = WriteOverflow
                    deriving (Show, Typeable)

instance Exception WriteException

-- | Perform a write action on a buffer pointed by the crypto pointer.
-- This expression @`runWrite` buf wr@ will raise `WriteOverflow`
-- /without/ writing any bytes if size of @buf@ is smaller than the
-- bytes that @wr@ has in it.
runWrite :: CryptoBuffer   -- ^ The buffer to which the bytes are to
                           -- be written.
         -> Write          -- ^ The write action.
         -> IO ()
runWrite  (CryptoBuffer sz cptr) (Write (summ, wr))
      | getSum summ > sz = throwIO WriteOverflow
      | otherwise        = WU.runWrite cptr wr

-- | The function tries the write action on the buffer and returns
-- `True` if successfull.
tryWrite :: CryptoBuffer  -- ^ The buffer to which the bytes are to
                          -- be written.
         -> Write         -- ^ The write action.
         -> IO Bool
tryWrite (CryptoBuffer sz cptr) (Write (summ, wr))
  | getSum summ > sz = return False
  | otherwise        = WU.runWrite cptr wr >> return True

-- | The expression @`writeStorable` a@ gives a write action that
-- stores a value @a@ in machine endian. The type of the value @a@ has
-- to be an instance of `Storable`. This should be used when we want
-- to talk with C functions and not when talking to the outside world
-- (otherwise this could lead to endian confusion). To take care of
-- endianness use the `write` combinator.
writeStorable :: Storable a => a -> Write
writeStorable a = Write (Sum $ byteSize a, WU.writeStorable a)


-- | The expression @`write` a@ gives a write action that stores a
-- value @a@. One needs the type of the value @a@ to be an instance of
-- `EndianStore`. Proper endian conversion is done irrespective of
-- what the machine endianness is. The man use of this write is to
-- serialize data for the consumption of the outside world.
write :: EndianStore a => a -> Write
write a = Write (Sum $ byteSize a, WU.write a)

-- | The combinator @writeBytes n b@ writes @b@ as the next @n@
-- consecutive bytes.
writeBytes :: Rounding n (BYTES Int) => n -> Word8 -> Write
writeBytes n b = Write (Sum $ roundFloor n, WU.writeBytes n b)

-- | Writes a strict bytestring.
writeByteString :: ByteString -> Write
writeByteString bs = Write (Sum n, WU.writeByteString bs)
  where n = BU.length bs
