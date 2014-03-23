-- | Module to write stuff to buffers. Necessary range checks are done
-- to make it safer than Raaz.Write.

{-# LANGUAGE FlexibleContexts   #-}
{-# LANGUAGE DeriveDataTypeable #-}
module Raaz.WriteSafe
       ( Write, write, writeStorable
       , WriteException(..)
       , writeBytes
       , runWrite
       ) where

import           Control.Exception
import           Control.Monad           ((>=>), void, when)
import           Data.Monoid
import           Data.Typeable
import           Data.Word               (Word8)
import           Foreign.Ptr             (castPtr)
import           Foreign.Storable

import           Raaz.Types
import           Raaz.Util.Ptr

import qualified Raaz.Write              as W

-- | The write type. Safer version of `W.Write`.
newtype Write = Write (CryptoBuffer -> IO CryptoBuffer)

instance Monoid Write where
  mempty                               = Write return
  mappend (Write first) (Write second) = Write (first >=> second)

data WriteException = WriteOverflow
                    deriving (Show, Typeable)

instance Exception WriteException

-- | Perform a write action on a buffer pointed by the crypto pointer.
runWrite :: CryptoBuffer -> Write -> IO ()
runWrite cptr (Write action) = void $ action cptr

-- | Safe version of `W.writeStorable`. Writes a value which is an
-- instance of Storable. This writes the value machine endian.
writeStorable :: Storable a => a -> Write
writeStorable a = Write $ \ (CryptoBuffer sz cptr) -> do
  when (sz < asz) $ throwIO WriteOverflow
  poke (castPtr cptr) a
  return $ CryptoBuffer (sz - asz) $ cptr `movePtr` byteSize a
  where
    asz = BYTES $ sizeOf a

-- | Safe version of `W.write`. Writes an instance of `EndianStore`. Endian safety is take into
-- account here. This is what you would need when you write network
-- packets for example.
write :: EndianStore a => a -> Write
write a = Write $ \ (CryptoBuffer sz cptr) -> do
  when (sz < asz) $ throwIO WriteOverflow
  store cptr a
  return $ CryptoBuffer (sz - asz) $ cptr `movePtr` byteSize a
  where
    asz = BYTES $ sizeOf a

-- | The combinator @writeBytes n b@ writes @b@ as the next @n@
-- consecutive bytes.
writeBytes :: CryptoCoerce n (BYTES Int) => n -> Word8 -> Write
writeBytes n b = Write $ \ (CryptoBuffer sz cptr) -> do
  when (sz < bytes) $ throwIO WriteOverflow
  memset cptr b bytes
  return (CryptoBuffer (sz - bytes) $ cptr `movePtr` n)
  where
    bytes = cryptoCoerce n :: BYTES Int
