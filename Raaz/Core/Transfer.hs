-- | Module to write stuff to buffers.

{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE TypeSynonymInstances       #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Raaz.Core.Transfer
       ( -- * Transfer actions.
         -- $transfer$
         -- ** Write action.
         WriteM, WriteIO, bytesToWrite, unsafeWrite
       , write, writeStorable, writeVector, writeStorableVector
       , writeBytes, writeByteString, skipWrite
       ) where

import           Control.Monad.IO.Class
import           Data.ByteString           (ByteString)
import           Data.String
import           Data.ByteString.Internal  (unsafeCreate)
import           Data.Monoid
import qualified Data.Vector.Generic       as G
import           Data.Word                 (Word8)
import           Foreign.Ptr               (castPtr)
import           Foreign.Storable

import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types.Endian
import           Raaz.Core.Types.Pointer
import           Raaz.Core.Util.ByteString as BU
import           Raaz.Core.Encode

-- | The monoid for transfering.
newtype TransferM m = TransferM { unTransferM :: m () }

instance Monad m => Monoid (TransferM m) where
  mempty        = TransferM $ return ()
  {-# INLINE mempty #-}

  mappend wa wb = TransferM $ unTransferM wa >> unTransferM wb
  {-# INLINE mappend #-}

  mconcat = TransferM . mapM_ unTransferM
  {-# INLINE mconcat #-}

-- | A action that transfers some stuff. It is nothing but an action that returns () on
-- input a pointer.
type TransferAction m = Pointer -> TransferM m

instance Monad m => LAction (BYTES Int) (TransferAction m) where
  offset <.> action = action . (offset<.>)
  {-# INLINE (<.>) #-}

instance Monad m => Distributive (BYTES Int) (TransferAction m)

type Transfer m = SemiR (TransferAction m) (BYTES Int)


makeTransfer :: LengthUnit u => u -> (Pointer -> m ()) -> Transfer m
{-# INLINE makeTransfer #-}
makeTransfer sz action = SemiR (TransferM . action) $ inBytes sz


-------------------------- Monoid for writing stuff --------------------------------------

-- | A write is an action which when executed using writes
-- bytes to its input buffer. `Write`s are monoid and hence can be
-- concatnated using the `<>` operator.
newtype WriteM m = WriteM { unWriteM :: Transfer m } deriving Monoid

-- | The default write action.
type Write = WriteM IO

-- | Returns the bytes that will be written when the write action is performed.
bytesToWrite :: WriteM m -> BYTES Int
bytesToWrite = semiRMonoid . unWriteM

-- | Perform the write action without any checks.
unsafeWrite :: WriteM m -> Pointer -> m ()
unsafeWrite wr =  unTransferM . semiRSpace (unWriteM wr)

{-
-- | The function tries to write the given `Write` action on the
-- buffer and returns `True` if successful.
tryWriting :: WriteM         -- ^ The write action.
           -> CryptoBuffer  -- ^ The buffer to which the bytes are to
                            -- be written.
           -> IO Bool
tryWriting wr cbuf = withCryptoBuffer cbuf $ \ sz cptr ->
  if sz < bytesToWriteM wr then return False
  else do unsafeWrite wr cptr; return True

-}


makeWrite     :: LengthUnit u => u -> (Pointer -> m ()) -> WriteM m
makeWrite sz  = WriteM . makeTransfer sz


-- | The expression @`writeStorable` a@ gives a write action that
-- stores a value @a@ in machine endian. The type of the value @a@ has
-- to be an instance of `Storable`. This should be used when we want
-- to talk with C functions and not when talking to the outside world
-- (otherwise this could lead to endian confusion). To take care of
-- endianness use the `write` combinator.
writeStorable :: (MonadIO m, Storable a) => a -> WriteM m
writeStorable a = WriteM $ makeTransfer (byteSize a) pokeIt
  where pokeIt = liftIO . flip poke a . castPtr
-- | The expression @`write` a@ gives a write action that stores a
-- value @a@. One needs the type of the value @a@ to be an instance of
-- `EndianStore`. Proper endian conversion is done irrespective of
-- what the machine endianness is. The man use of this write is to
-- serialize data for the consumption of the outside world.
write :: (MonadIO m, EndianStore a) => a -> WriteM m
write a = makeWrite (byteSize a) $ liftIO . flip store a

-- | The vector version of `writeStorable`.
writeStorableVector :: (Storable a, G.Vector v a, MonadIO m) => v a -> WriteM m
{-# INLINE writeStorableVector #-}
writeStorableVector = G.foldl' foldFunc mempty
  where foldFunc w a =  w <> writeStorable a

{-

TODO: This function can be slow due to the fact that each time we use
the semi-direct product, we incur a cost due to the lambda being not
lifted.

-}

-- | The vector version of `write`.
writeVector :: (EndianStore a, G.Vector v a, MonadIO m) => v a -> WriteM m
{-# INLINE writeVector #-}
{-# TODO: improve this using the fact that the size is known #-}
writeVector = G.foldl' foldFunc mempty
  where foldFunc w a =  w <> write a
{- TODO: Same as in writeStorableVector -}


-- | The combinator @writeBytes n b@ writes @b@ as the next @n@
-- consecutive bytes.
writeBytes :: (LengthUnit n, MonadIO m) => Word8 -> n -> WriteM m
writeBytes w8 n = makeWrite n memsetIt
  where memsetIt cptr = liftIO $ memset cptr w8 n

-- | Writes a strict bytestring.
writeByteString :: MonadIO m => ByteString -> WriteM m
writeByteString bs = makeWrite (BU.length bs) $ liftIO  . BU.unsafeCopyToPointer bs

-- | A write action that just skips over the given bytes.
skipWrite :: (LengthUnit u, Monad m) => u -> WriteM m
skipWrite = flip makeWrite $ const $ return ()

instance MonadIO m => IsString (WriteM m)  where
  fromString = writeByteString . fromString

instance Encodable (WriteM IO) where
  {-# INLINE toByteString #-}
  toByteString w  = unsafeCreate n $ unsafeWrite w . castPtr
    where BYTES n = bytesToWrite w

  {-# INLINE unsafeFromByteString #-}
  unsafeFromByteString = writeByteString

  {-# INLINE fromByteString #-}
  fromByteString       = Just . writeByteString
