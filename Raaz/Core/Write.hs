-- | Module to write stuff to buffers. As opposed to similar functions
-- exposed in "Raaz.Core.Write.Unsafe", the writes exposed here are
-- safe as necessary range checks are done on the buffer before
-- writing stuff to it.

{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE TypeSynonymInstances       #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}

module Raaz.Core.Write
       ( Write, bytesToWrite, tryWriting, unsafeWrite
       , write, writeStorable, writeVector, writeStorableVector
       , writeBytes, writeByteString
       ) where

import           Data.ByteString           (ByteString)
import           Data.ByteString.Internal  (unsafeCreate)
import           Data.Monoid
import qualified Data.Vector.Generic       as G
import           Data.Word                 (Word8)
import           Foreign.Ptr               (castPtr)
import           Foreign.Storable

import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString as BU
import           Raaz.Core.Util.Ptr
import           Raaz.Core.Encode

-- | The monoid for write.
newtype WriteM = WriteM { unWriteM :: IO () }

instance Monoid WriteM where
  mempty        = WriteM $ return ()
  mappend wa wb = WriteM $ unWriteM wa >> unWriteM wb

-- | A write action is nothing but an IO action that returns () on
-- input a pointer.
type WriteAction = CryptoPtr -> WriteM

type BytesMonoid = Sum (BYTES Int)

instance LAction BytesMonoid WriteAction where
  m <.> action = action . (m<.>)
instance Distributive BytesMonoid WriteAction

-- | A write is an action which when executed using `runWrite` writes
-- bytes to the input buffer. It is similar to the `WU.Write` type
-- exposed from the "Raaz.Write.Unsafe" module except that it keeps
-- track of the total bytes that would be written to the buffer if the
-- action is run. The `runWrite` action will raise an error if the
-- buffer it is provided with is of size smaller. `Write`s are monoid
-- and hence can be concatnated using the `<>` operator.
type Write = SemiR WriteAction BytesMonoid

-- | Create a write action.
makeWrite :: BYTES Int -> (CryptoPtr -> IO ()) -> Write
makeWrite sz action = SemiR (WriteM . action, Sum sz)

-- | Returns the bytes that will be written when the write action is performed.
bytesToWrite :: Write -> BYTES Int
bytesToWrite = getSum . semiRMonoid

-- | Perform the write action without any checks.
unsafeWrite :: Write -> CryptoPtr -> IO ()
unsafeWrite wr =  unWriteM . semiRSpace wr

-- | The function tries to write the given `Write` action on the
-- buffer and returns `True` if successful.
tryWriting :: Write         -- ^ The write action.
           -> CryptoBuffer  -- ^ The buffer to which the bytes are to
                            -- be written.
           -> IO Bool
tryWriting wr cbuf = withCryptoBuffer cbuf $ \ sz cptr ->
  if sz < bytesToWrite wr then return False
  else do unsafeWrite wr cptr; return True


-- | The expression @`writeStorable` a@ gives a write action that
-- stores a value @a@ in machine endian. The type of the value @a@ has
-- to be an instance of `Storable`. This should be used when we want
-- to talk with C functions and not when talking to the outside world
-- (otherwise this could lead to endian confusion). To take care of
-- endianness use the `write` combinator.
writeStorable :: Storable a => a -> Write
writeStorable a = makeWrite (byteSize a) pokeIt
  where pokeIt = flip poke a . castPtr
-- | The expression @`write` a@ gives a write action that stores a
-- value @a@. One needs the type of the value @a@ to be an instance of
-- `EndianStore`. Proper endian conversion is done irrespective of
-- what the machine endianness is. The man use of this write is to
-- serialize data for the consumption of the outside world.
write :: EndianStore a => a -> Write
write a = makeWrite (byteSize a) $ flip store a

-- | The vector version of `writeStorable`.
writeStorableVector :: (Storable a, G.Vector v a) => v a -> Write
{-# INLINE writeStorableVector #-}
writeStorableVector = G.foldl' foldFunc mempty
  where foldFunc w a =  w <> writeStorable a

-- | The vector version of `write`.
writeVector :: (EndianStore a, G.Vector v a) => v a -> Write
{-# INLINE writeVector #-}
writeVector = G.foldl' foldFunc mempty
  where foldFunc w a =  w <> write a

-- | The combinator @writeBytes n b@ writes @b@ as the next @n@
-- consecutive bytes.
writeBytes :: LengthUnit n => Word8 -> n -> Write
writeBytes w8 n = makeWrite (inBytes n) memsetIt
  where memsetIt cptr = memset cptr w8 n

-- | Writes a strict bytestring.
writeByteString :: ByteString -> Write
writeByteString bs = makeWrite (BU.length bs) $  BU.unsafeCopyToCryptoPtr bs


instance Encodable Write where

  toByteString w  = unsafeCreate n $ unsafeWrite w . castPtr
    where BYTES n = bytesToWrite w

  unsafeFromByteString = writeByteString

  fromByteString       = Just . writeByteString
