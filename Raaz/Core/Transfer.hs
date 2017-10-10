-- | Module to reading from and writing into buffers.

{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE TypeSynonymInstances       #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}


module Raaz.Core.Transfer
       ( -- * Transfer actions.
         -- $transfer$

         -- ** Read action
         ReadM, ReadIO, bytesToRead, unsafeRead
       , readBytes, readInto

         -- ** Write action.
       ,  WriteM, WriteIO, bytesToWrite, unsafeWrite
       , write, writeStorable, writeVector, writeStorableVector
       , writeFrom, writeBytes
       , padWrite, prependWrite, glueWrites
       , writeByteString, skipWrite

       ) where

import           Control.Monad.IO.Class
import           Data.ByteString           (ByteString)
import           Data.Proxy
import           Data.String
import           Data.ByteString.Internal  (unsafeCreate)
import           Data.Monoid
import qualified Data.Vector.Generic       as G
import           Data.Word                 (Word8)
import           Foreign.Ptr               (castPtr, Ptr)
import           Foreign.Storable          ( Storable, poke )

import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types.Copying
import           Raaz.Core.Types.Endian
import           Raaz.Core.Types.Pointer
import           Raaz.Core.Util.ByteString as BU
import           Raaz.Core.Encode
import           Raaz.Core.Proxy

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
-- two types, the `ReadM` and the `WriteM` type which deals with these
-- two aspects. Both these actions keep track of the number of bytes
-- that they transfer.

-- Complex reads and writes can be constructed using the monoid
-- instance of these types.



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

instance LAction (BYTES Int) (TransferAction m) where
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

-- | An element of type `WriteM m` is an action which when executed transfers bytes
-- /into/ its input buffer.  The type @`WriteM` m@ forms a monoid and
-- hence can be concatnated using the `<>` operator.
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
writeStorable a = WriteM $ makeTransfer (sizeOf $ pure a) pokeIt
  where pokeIt = liftIO . flip poke a . castPtr
-- | The expression @`write` a@ gives a write action that stores a
-- value @a@. One needs the type of the value @a@ to be an instance of
-- `EndianStore`. Proper endian conversion is done irrespective of
-- what the machine endianness is. The man use of this write is to
-- serialize data for the consumption of the outside world.
write :: (MonadIO m, EndianStore a) => a -> WriteM m
write a = makeWrite (sizeOf $ pure a) $ liftIO . flip (store . castPtr) a

-- | Write many elements from the given buffer
writeFrom :: (MonadIO m, EndianStore a) => Int -> Src (Ptr a) -> WriteM m
writeFrom n src = makeWrite (sz src)
                  $ \ ptr -> liftIO  $ copyToBytes (destination ptr) src n
  where sz = (*) (toEnum n) . sizeOf . proxy
        proxy :: Src (Ptr a) -> Proxy a
        proxy = proxyUnwrap . proxyUnwrap . pure
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

{-
-- | The write action @padWriteTo w n wr@ is wr padded with the byte @w@ so that the total length
-- is n. If the total bytes written by @wr@ is greater than @n@ then this throws an error.
padWriteTo :: ( LengthUnit n, MonadIO m)
              => Word8     -- ^ the padding byte to use
              -> n         -- ^ the total length to pad to
              -> WriteM m  -- ^ the write that needs padding
              -> WriteM m
padWriteTo w8 n wrm | pl < 0    = error "padToLength: padding length smaller than total length"
                    | otherwise = wrm <> writeBytes w8 n
  where pl = inBytes n - bytesToWrite wrm

-}

-- | The combinator @glueWrites w n hdr ftr@ is equivalent to
-- @hdr <> glue <> ftr@ where the write @glue@ writes as many bytes
-- @w@ so that the total length is aligned to the boundary @n@.
glueWrites :: ( LengthUnit n, MonadIO m)
           =>  Word8    -- ^ The bytes to use in the glue
           -> n        -- ^ The length boundary to align to.
           -> WriteM m -- ^ The header write
           -> WriteM m -- ^ The footer write
           -> WriteM m
glueWrites w8 n hdr ftr = hdr <> writeBytes w8 lglue <> ftr
  where lhead   = bytesToWrite hdr
        lfoot   = bytesToWrite ftr
        lexceed = (lhead + lfoot) `rem` nBytes  -- bytes exceeding the boundary.
        lglue   = nBytes - lexceed
        nBytes  = inBytes n



-- | The write action @prependWrite w n wr@ is wr pre-pended with the byte @w@ so that the total length
-- ends at a multiple of @n@.
prependWrite  :: ( LengthUnit n, MonadIO m)
              => Word8     -- ^ the byte to pre-pend with.
              -> n         -- ^ the length to align the message to
              -> WriteM m  -- ^ the message that needs pre-pending
              -> WriteM m
prependWrite w8 n = glueWrites w8 n mempty

-- | The write action @padWrite w n wr@ is wr padded with the byte @w@ so that the total length
-- ends at a multiple of @n@.
padWrite :: ( LengthUnit n, MonadIO m)
         => Word8     -- ^ the padding byte to use
         -> n         -- ^ the length to align message to
         -> WriteM m  -- ^ the message that needs padding
         -> WriteM m
padWrite w8 n = flip (glueWrites w8 n) mempty

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

-- | The `ReadM` is the type that captures the act of reading from a buffer
-- and possibly doing some action on the bytes read. Although
-- inaccurate, it is helpful to think of elements of `ReadM` as action
-- that on an input buffer transfers data from it to some unspecified
-- source.
--
-- Read actions form a monoid with the following semantics: if @r1@
-- and @r2@ are two read actions then @r1 `<>` r2@ first reads the
-- data associated from @r1@ and then the read associated with the
-- data @r2@.

newtype ReadM m = ReadM { unReadM :: Transfer m} deriving Monoid

-- | A read io-action.
type ReadIO = ReadM IO

-- | Function that explicitly constructs a write action.
makeRead     :: LengthUnit u => u -> (Pointer -> m ()) -> ReadM m
makeRead sz  = ReadM . makeTransfer sz


-- | The expression @bytesToRead r@ gives the total number of bytes that
-- would be read from the input buffer if the action @r@ is performed.
bytesToRead :: ReadM m -> BYTES Int
bytesToRead = semiRMonoid . unReadM

-- | The action @unsafeRead r ptr@ results in reading @bytesToRead r@
-- bytes from the buffer pointed by @ptr@. This action is unsafe as it
-- will not (and cannot) check if the action reads beyond what is
-- legally stored at @ptr@.
unsafeRead :: ReadM m
           -> Pointer   -- ^ The pointer for the buffer to be written into.
           -> m ()
unsafeRead rd =  unTransferM . semiRSpace (unReadM rd)

-- | The action @readBytes sz dptr@ gives a read action, which if run on
-- an input buffer, will transfers @sz@ to the destination buffer
-- pointed by @dptr@. Note that it is the responsibility of the user
-- to make sure that @dptr@ has enough space to receive @sz@ units of
-- data if and when the read action is executed.
readBytes :: ( LengthUnit sz, MonadIO m)
          => sz             -- ^ how much to read.
          -> Dest Pointer   -- ^ buffer to read the bytes into
          -> ReadM m
readBytes sz dest = makeRead sz
                    $ \ ptr -> liftIO  $ memcpy dest (source ptr) sz

-- | The action @readInto n dptr@ gives a read action which if run on an
-- input buffer, will transfers @n@ elements of type @a@ into the
-- buffer pointed by @dptr@. In particular, the read action @readInto n
-- dptr@ is the same as @readBytes (fromIntegral n :: BYTES Int) dptr@
-- when the type @a@ is `Word8`.
readInto :: (EndianStore a, MonadIO m)
         => Int             -- ^ how many elements to read.
         -> Dest (Ptr a)    -- ^ buffer to read the elements into
         -> ReadM m
readInto n dest = makeRead (sz dest)
                  $ \ ptr -> liftIO $ copyFromBytes dest (source ptr) n
  where sz  = (*) (toEnum n) . sizeOf . proxy
        proxy :: Dest (Ptr a) -> Proxy a
        proxy = proxyUnwrap . proxyUnwrap . pure
