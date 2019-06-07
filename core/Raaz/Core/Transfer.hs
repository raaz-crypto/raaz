-- | Module to reading from and writing into buffers.
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}

module Raaz.Core.Transfer
       ( -- * Transfer actions.
         -- $transfer$
         ReadM, ReadIO
       , consume, consumeStorable, consumeParse
       , readBytes, readInto
       , WriteM, WriteIO
       , write, writeStorable, writeVector, writeStorableVector
       , writeFrom, writeBytes
       , padWrite, prependWrite, glueWrites
       , writeByteString
       , transferSize
       , liftTransfer
       , skip, interleave
       , unsafeTransfer
       ) where

import           Control.Monad.IO.Class
import           Data.ByteString           (ByteString)
import           Data.ByteString.Internal  (unsafeCreate)


import qualified Data.Vector.Generic       as G
import           Foreign.Ptr               (castPtr, Ptr)
import           Foreign.Storable          ( Storable, poke )

import           Raaz.Core.Prelude
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Parse.Applicative hiding (skip)
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
-- two types, the `ReadM` and the `WriteM` type which deals with these
-- two aspects. Both these actions keep track of the number of bytes
-- that they transfer.

-- Complex reads and writes can be constructed using the monoid
-- instance of these types.


data Mode = ReadFromBuffer
          | WriteToBuffer


-- | This monoid captures a transfer action.
newtype TransferM (t :: Mode) m = TransferM { unTransferM :: m () }

instance Monad m => Semigroup (TransferM t m) where
  (<>) wa wb = TransferM $ unTransferM wa >> unTransferM wb
  {-# INLINE (<>) #-}

instance Monad m => Monoid (TransferM t m) where
  mempty        = TransferM $ return ()
  {-# INLINE mempty #-}

  mappend = (<>)
  {-# INLINE mappend #-}

  mconcat = TransferM . mapM_ unTransferM
  {-# INLINE mconcat #-}

-- | A action that transfers bytes from its input pointer. Transfer
-- could either be writing or reading.
type TransferAction t m = Pointer -> TransferM t m

instance LAction (BYTES Int) (TransferAction t m) where
  offset <.> action = action . (offset<.>)
  {-# INLINE (<.>) #-}

instance Monad m => Distributive (BYTES Int) (TransferAction t m)

-- | An element of type `Tranfer t m` is an action which when executed
-- transfers bytes /into/ or out of its input buffer.  The type
-- @`Transfer` t m@ forms a monoid and hence can be concatenated using
-- the `<>` operator.

type Transfer t m = SemiR (TransferAction t m) (BYTES Int)

-- | Given a function to lift @m@-actions to @n@-actions lifts the
-- associated transfers.
liftTransfer :: (m () -> n ()) -- ^ The lifting function
             -> Transfer t m
             -> Transfer t n
liftTransfer f tf = makeTransfer sz action
  where sz     = transferSize tf
        action = f . unsafeTransfer tf



-- | The `WriteM` is the type that captures the act of writing to a
-- buffer. Although inaccurate, it is helpful to think of elements of
-- `WriteM` as source of bytes of a fixed size.
--
-- Write actions form a monoid with the following semantics: if @w1@
-- and @w2@ are two write actions then @w1 `<>` w2@ first writes the
-- data associated from @w1@ and then the writes the data associated
-- with  @w2@.
type WriteM m     = Transfer 'WriteToBuffer m


------------------------  Read action ----------------------------

-- | The `ReadM` is the type that captures the act of reading from a
-- buffer and possibly doing some action on the bytes read. Although
-- inaccurate, it is helpful to think of elements of `ReadM` as action
-- that on an input buffer transfers data from it to some unspecified
-- source.
--
-- Read actions form a monoid with the following semantics: if @r1@
-- and @r2@ are two read actions then @r1 `<>` r2@ first reads the the
-- data associated with @r1@ and then reads the data associated with
-- @r2@.
type ReadM  m     = Transfer 'ReadFromBuffer m

-- | The IO specialised variant of `WriteM`
type WriteIO      = WriteM IO

-- | The IO specialised variant of `ReadM`
type ReadIO       = ReadM IO

-- | Make an explicit transfer action given.
makeTransfer :: LengthUnit u => u -> (Pointer -> m ()) -> Transfer t m
{-# INLINE makeTransfer #-}
makeTransfer sz action = SemiR (TransferM . action) $ inBytes sz

-- | This combinator can be used to interleave a pure action between
-- transfers.
interleave :: Functor m => m a -> Transfer t m
interleave  = makeTransfer (0 :: BYTES Int) . const . void

-- | Returns the bytes that will be written when the write action is performed.
transferSize :: Transfer t m -> BYTES Int
transferSize = semiRMonoid

-- | Perform the transfer without checking the bounds.
unsafeTransfer :: Transfer t m
               -> Pointer       -- ^ The pointer to the buffer to/from which transfer occurs.
               -> m ()
unsafeTransfer tr = unTransferM . semiRSpace tr

-- | The transfer @skip l@ skip ahead by an offset @l@. If it is a
-- read, it does not read the next @l@ positions. If it is a write it
-- does not mutate the next @l@ positions.
skip :: (LengthUnit l, Monad m) => l -> Transfer t m
skip = flip makeTransfer $ const $ return ()

-------------------------- Monoids for consuming stuff ------------------------------------

-- | Given a parser @p :: Parser a@ for parsing @a@ and @act :: a -> m
-- b@ consuming a, @consumeParse p act@, gives a reader that parses a
-- from the input buffer passing it to the action act.
consumeParse :: MonadIO m => Parser a -> (a -> m b) -> ReadM m
consumeParse p action = makeTransfer (parseWidth p) $
                        \ ptr -> liftIO (unsafeRunParser p ptr) >>= void . action

-- | Reads @a@ from the buffer and supplies it to the action. The
-- value read is independent of the endianness of the underlying.
consume :: (EndianStore a, MonadIO m)
        => (a -> m b)
        -> ReadM m
consume = consumeParse parse

-- | Similar to @consume@ but does not take care of adjusting for
-- endianness. Use therefore limited to internal buffers.
consumeStorable :: (Storable a, MonadIO m)
                => (a -> m b)
                -> ReadM m
consumeStorable = consumeParse parseStorable

-------------------------- Monoid for writing stuff --------------------------------------


-- | The expression @`writeStorable` a@ gives a write action that
-- stores a value @a@ in machine endian. The type of the value @a@ has
-- to be an instance of `Storable`. This should be used when we want
-- to talk with C functions and not when talking to the outside world
-- (otherwise this could lead to endian confusion). To take care of
-- endianness use the `write` combinator.
writeStorable :: (MonadIO m, Storable a) => a -> WriteM m
writeStorable a = makeTransfer (sizeOf $ pure a) pokeIt
  where pokeIt = liftIO . flip poke a . castPtr
-- | The expression @`write` a@ gives a write action that stores a
-- value @a@. One needs the type of the value @a@ to be an instance of
-- `EndianStore`. Proper endian conversion is done irrespective of
-- what the machine endianness is. The man use of this write is to
-- serialize data for the consumption of the outside world.
write :: (MonadIO m, EndianStore a) => a -> WriteM m
write a = makeTransfer (sizeOf $ pure a) $ liftIO . flip (store . castPtr) a

-- | Write many elements from the given buffer
writeFrom :: (MonadIO m, EndianStore a) => Int -> Src (Ptr a) -> WriteM m
writeFrom n src = makeTransfer (sz src)
                  $ \ ptr -> liftIO  $ copyToBytes (destination ptr) src n
  where sz = (*) (toEnum n) . sizeOf . proxy
        proxy :: Src (Ptr a) -> Proxy a
        proxy = const Proxy

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
writeBytes w8 n = makeTransfer n memsetIt
  where memsetIt cptr = liftIO $ memset cptr w8 n

-- | The combinator @glueWrites w n hdr ftr@ is equivalent to @hdr <>
-- glue <> ftr@ where the write @glue@ writes just enough bytes @w@ so
-- that the total length is aligned to the boundary @n@.
glueWrites :: ( LengthUnit n, MonadIO m)
           => Word8    -- ^ The bytes to use in the glue
           -> n        -- ^ The length boundary to align to.
           -> WriteM m -- ^ The header write
           -> WriteM m -- ^ The footer write
           -> WriteM m
glueWrites w8 n hdr ftr = hdr <> writeBytes w8 lglue <> ftr
  where lhead   = transferSize hdr
        lfoot   = transferSize ftr
        lexceed = (lhead + lfoot) `rem` nBytes  -- bytes exceeding the boundary.
        lglue   = if lexceed > 0 then nBytes - lexceed else 0
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

-------------  Reading and writing byte strings -----------------------------------
-- | Writes a strict bytestring.
writeByteString :: MonadIO m => ByteString -> WriteM m
writeByteString bs = makeTransfer (BU.length bs) $ liftIO  . BU.unsafeCopyToPointer bs

-- | The action @readBytes sz dptr@ gives a read action, which if run on
-- an input buffer, will transfers @sz@ to the destination buffer
-- pointed by @dptr@. Note that it is the responsibility of the user
-- to make sure that @dptr@ has enough space to receive @sz@ units of
-- data if and when the read action is executed.
readBytes :: ( LengthUnit sz, MonadIO m)
          => sz             -- ^ how much to read.
          -> Dest Pointer   -- ^ buffer to read the bytes into
          -> ReadM m
readBytes sz dest = makeTransfer sz
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
readInto n dest = makeTransfer (sz dest)
                  $ \ ptr -> liftIO $ copyFromBytes dest (source ptr) n
  where sz  = (*) (toEnum n) . sizeOf . proxy
        proxy :: Dest (Ptr a) -> Proxy a
        proxy = const Proxy

instance MonadIO m => IsString (WriteM m)  where
  fromString = writeByteString . fromString

instance Encodable WriteIO where
  {-# INLINE toByteString #-}
  toByteString w  = unsafeCreate n $ unsafeTransfer w . castPtr
    where BYTES n = transferSize w

  {-# INLINE unsafeFromByteString #-}
  unsafeFromByteString = writeByteString

  {-# INLINE fromByteString #-}
  fromByteString       = Just . writeByteString
