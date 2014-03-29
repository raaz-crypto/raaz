-- | Module to write stuff to buffers. Necessary range checks are done
-- to make it safer than Raaz.Write.

{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Write
       ( Write, write, writeStorable
       , WriteException(..)
       , writeBytes, writeByteString
       , runWrite
       ) where

import           Control.Exception
import           Data.ByteString      (ByteString)
import           Data.Monoid
import           Data.Typeable
import           Data.Word            (Word8)
import           Foreign.Storable

import           Raaz.Types
import           Raaz.Util.Ptr
import           Raaz.Util.ByteString as BU

import qualified Raaz.Write.Unsafe    as WU

-- | The write type. Safer version of `W.Write`.
newtype Write = Write (Sum (BYTES Int), WU.Write)
              deriving Monoid

data WriteException = WriteOverflow
                    deriving (Show, Typeable)

instance Exception WriteException

-- | Perform a write action on a buffer pointed by the crypto pointer.
runWrite :: CryptoBuffer -> Write -> IO ()
runWrite  (CryptoBuffer sz cptr) (Write (summ, wr))
      | getSum summ > sz = throwIO WriteOverflow
      | otherwise        = WU.runWrite cptr wr

-- | Safe version of `WU.writeStorable`. Writes a value which is an
-- instance of Storable. This writes the value machine endian.
writeStorable :: Storable a => a -> Write
writeStorable a = Write (Sum $ byteSize a, WU.writeStorable a)

-- | Safe version of `WU.write`. Writes an instance of
-- `EndianStore`. Endian safety is take into account here. This is
-- what you would need when you write network packets for example.
write :: EndianStore a => a -> Write
write a = Write (Sum $ byteSize a, WU.write a)

-- | The combinator @writeBytes n b@ writes @b@ as the next @n@
-- consecutive bytes.
writeBytes :: CryptoCoerce n (BYTES Int) => n -> Word8 -> Write
writeBytes n b = Write (Sum $ cryptoCoerce n, WU.writeBytes n b)

-- | Writes a strict bytestring.
writeByteString :: ByteString -> Write
writeByteString bs = Write (Sum n, WU.writeByteString bs)
  where n = BU.length bs
