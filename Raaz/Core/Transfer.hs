-- | Module to reading from and writing into buffers.

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
       , writeFrom, writeBytes, writeByteString, skipWrite
         -- ** Read action
       , ReadM, ReadIO, bytesToRead, unsafeRead
       , readBytes, readInto

       ) where

import           Control.Monad.IO.Class
import           Data.ByteString           (ByteString)
import           Data.String
import           Data.ByteString.Internal  (unsafeCreate)
import           Data.Monoid
import qualified Data.Vector.Generic       as G
import           Data.Word                 (Word8)
import           Foreign.Ptr               (castPtr, Ptr)
import           Foreign.Storable

import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types.Copying
import           Raaz.Core.Types.Endian
import           Raaz.Core.Types.Pointer
import           Raaz.Core.Util.ByteString as BU
import           Raaz.Core.Encode

-- $transfer$
--
-- Low level buffer operations are problematic portions of any
-- crypto-library. Buffers are usually represented by the starting
-- pointer and one needs to keep track of the buffer sizes
-- carefully. An operation that writes into a buffer, if it writes
-- beyond the actual size of the buffer, can lead to a possible remote
-- code execution. On the other hand, when reading from a buffer, if
-- we read beyond the buffer it can leak private data to the attacker
-- (as in the case of Heart bleed bug). This module is indented to
-- give a relatively high level interface to this problem. We expose
-- two types, the `Read` and the `Write` type which deals with these
-- to aspects which are essentially functions from a pointer to an
-- `IO` action. A `Read` action transfers bytes from the buffer where
-- as a `Write` action transfers data into a buffer. Both these
-- actions keep track of the number of bytes that they transfer,
-- either from the buffer as in the case of a `Read` action, or into
-- the buffer as in the case of a `Write` action.
--
-- Complex reads and writes can be constructed using the monoid
-- instance of these types. For example, the `mempty` for the type
-- `Read` is a read action that reads nothing from the input
-- buffer. If @r1@ and @r2@ are two read actions then @r1 <> r2@
-- performs the read @r1@ followed by the read @r2@.  The necessary
-- pointer arithmetic involved in these actions are automatically
-- taken care of by the monoid instance. Similarly, for the type
-- `Write`, the unit element `mempty` writes nothing into the buffer
-- and the @w1 <> w2@ performs the action @w1@ followed by @w2@.


-- | This monoid captures a transfer action.
newtype TransferM m = TransferM { unTransferM :: m () }

instance Monad m => Monoid (TransferM m) where
  mempty        = TransferM $ return ()
  {-# INLINE mempty #-}

  mappend wa wb = TransferM $ unTransferM wa >> unTransferM wb
  {-# INLINE mappend #-}

  mconcat = TransferM . mapM_ unTransferM
  {-# INLINE mconcat #-}

-- | A action that transfers bytes from its input pointer. Transfer
-- could either be writing or reading.
type TransferAction m = Pointer -> TransferM m

instance Monad m => LAction (BYTES Int) (TransferAction m) where
  offset <.> action = action . (offset<.>)
  {-# INLINE (<.>) #-}

instance Monad m => Distributive (BYTES Int) (TransferAction m)

-- | Byte transfers that keep track of the number of bytes that were
-- transferred (from/into) its input buffer.
type Transfer m = SemiR (TransferAction m) (BYTES Int)

-- | Make an explicit transfer action given.
makeTransfer :: LengthUnit u => u -> (Pointer -> m ()) -> Transfer m
{-# INLINE makeTransfer #-}
makeTransfer sz action = SemiR (TransferM . action) $ inBytes sz


-------------------------- Monoid for writing stuff --------------------------------------

-- | A write is an action that transfers bytes /into/ its input buffer.  `Write`s are monoid and hence can be
-- concatnated using the `<>` operator.
newtype WriteM m = WriteM { unWriteM :: Transfer m } deriving Monoid

-- | A write io-action.
type WriteIO = WriteM IO

-- | Returns the bytes that will be written when the write action is performed.
bytesToWrite :: WriteM m -> BYTES Int
bytesToWrite = semiRMonoid . unWriteM

-- | Perform the write action without any checks of the buffer
unsafeWrite :: WriteM m
            -> Pointer   -- ^ The pointer for the buffer to be written into.
            -> m ()
unsafeWrite wr =  unTransferM . semiRSpace (unWriteM wr)

-- | Function that explicitly constructs a write action.
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
write a = makeWrite (byteSize a) $ liftIO . flip (store . castPtr) a

-- | Write many elements from the given buffer
writeFrom :: (MonadIO m, EndianStore a) => Int -> Src (Ptr a) -> WriteM m
writeFrom n src = makeWrite (sz undefined src)
                  $ \ ptr -> do liftIO  $ copyToBytes (destination ptr) src n
  where sz :: Storable a => a -> Src (Ptr a) -> BYTES Int
        sz a _ = toEnum n * byteSize a

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
{- TODO: improve this using the fact that the size is known -}

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

------------------------  Read action ----------------------------

-- | A read action is an action that transfers bytes out of its
-- argument buffer. Read actions form a monoid and hence two read
-- actions @r1@ and @r2@ can be combined using `<>`.
newtype ReadM m = ReadM { unReadM :: Transfer m} deriving Monoid

-- | A read io-action.
type ReadIO = ReadM IO

-- | Function that explicitly constructs a write action.
makeRead     :: LengthUnit u => u -> (Pointer -> m ()) -> ReadM m
makeRead sz  = ReadM . makeTransfer sz


-- | Returns the bytes that will be written when the write action is
-- performed.
bytesToRead :: ReadM m -> BYTES Int
bytesToRead = semiRMonoid . unReadM

-- | Perform the write action without any checks of the buffer
unsafeRead :: ReadM m
           -> Pointer   -- ^ The pointer for the buffer to be written into.
           -> m ()
unsafeRead rd =  unTransferM . semiRSpace (unReadM rd)

-- | Read bytes into a given buffer.
readBytes :: ( LengthUnit sz, MonadIO m)
          => sz             -- ^ how much to read.
          -> Dest Pointer   -- ^ buffer to read the bytes into
          -> ReadM m
readBytes sz dest = makeRead sz
                    $ \ ptr -> liftIO  $ memcpy dest (source ptr) sz

-- | Read elements of endian store type into the given buffer.
readInto :: (EndianStore a, MonadIO m)
         => Int             -- ^ how many elements to read.
         -> Dest (Ptr a)    -- ^ buffer to read the elements into
         -> ReadM m
readInto n dest = makeRead (sz undefined dest)
                  $ \ ptr -> liftIO $ copyFromBytes dest (source ptr) n
  where sz :: Storable a => a -> Dest (Ptr a) -> BYTES Int
        sz a _ = toEnum n * byteSize a
