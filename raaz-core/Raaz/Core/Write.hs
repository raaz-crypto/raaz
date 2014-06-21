-- | Module to write stuff to buffers. As opposed to similar functions
-- exposed in "Raaz.Core.Write.Unsafe", the writes exposed here are
-- safe as necessary range checks are done on the buffer before
-- writing stuff to it.

{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}

module Raaz.Core.Write
       ( Write, tryWriting
       , write, writeStorable
       , writeBytes, writeByteString
       ) where

import           Data.ByteString           (ByteString)
import           Data.Monoid
import           Data.Word                 (Word8)
import           Foreign.Storable

import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString as BU
import           Raaz.Core.Util.Ptr

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

-- | The function tries to write the given `Write` action on the
-- buffer and returns `True` if successful.
tryWriting :: Write         -- ^ The write action.
           -> CryptoBuffer  -- ^ The buffer to which the bytes are to
                            -- be written.
           -> IO Bool
tryWriting (Write (summ, wr)) (CryptoBuffer sz cptr)
  | getSum summ > sz = return False
  | otherwise        = WU.runWrite cptr wr >> return True

-- | This function converts an unsafe write to a safe write by adding
-- a length bound
withBound  :: LengthUnit l
            => WU.Write
            -> l
            -> Write
withBound  wu l = Write (Sum $ inBytes l, wu)

-- | The expression @`writeStorable` a@ gives a write action that
-- stores a value @a@ in machine endian. The type of the value @a@ has
-- to be an instance of `Storable`. This should be used when we want
-- to talk with C functions and not when talking to the outside world
-- (otherwise this could lead to endian confusion). To take care of
-- endianness use the `write` combinator.
writeStorable :: Storable a => a -> Write
writeStorable a = WU.writeStorable a `withBound` byteSize a


-- | The expression @`write` a@ gives a write action that stores a
-- value @a@. One needs the type of the value @a@ to be an instance of
-- `EndianStore`. Proper endian conversion is done irrespective of
-- what the machine endianness is. The man use of this write is to
-- serialize data for the consumption of the outside world.
write :: EndianStore a => a -> Write
write a = WU.write a `withBound` byteSize a

-- | The combinator @writeBytes n b@ writes @b@ as the next @n@
-- consecutive bytes.
writeBytes :: LengthUnit n => Word8 -> n -> Write
writeBytes w8 n = WU.writeBytes w8 n `withBound` n

-- | Writes a strict bytestring.
writeByteString :: ByteString -> Write
writeByteString bs = WU.writeByteString bs `withBound` BU.length bs
