{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}

-- |
--
-- Module      : Raaz.Core.Transfer.Unsafe
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--

module Raaz.Core.Transfer.Unsafe
       ( -- * Transfer actions.
         -- $transfer$
         Transfer, ReadFrom, WriteTo
       , unsafeMakeTransfer
       , unsafeTransfer
       , unsafeInterleave
       , unsafeReadIntoPtr, unsafeReadInto
       , unsafeWriteFrom
       , unsafeWriteFromPtr
       , writeByteString
       , transferSize
       ) where

import           Data.ByteString          (ByteString)
import           Data.ByteString.Internal (unsafeCreate)

import           Raaz.Core.Prelude
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types.Copying
import           Raaz.Core.Types.Endian
import           Raaz.Core.Types.Pointer
import           Raaz.Core.Encode
import           Raaz.Core.Util.ByteString as BU

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
-- two types, the `ReadM` and the `Write` type which deals with these
-- two aspects. Both these actions keep track of the number of bytes
-- that they transfer.

-- Complex reads and writes can be constructed using the monoid
-- instance of these types.

data Mode = ReadFromBuffer
          | WriteToBuffer


-- | This monoid captures a transfer action.
newtype TransferM (t :: Mode) = TransferM { unTransferM :: IO () }

instance Semigroup (TransferM t) where
  (<>) wa wb = TransferM $ unTransferM wa >> unTransferM wb
  {-# INLINE (<>) #-}

instance Monoid (TransferM t) where
  mempty        = TransferM $ return ()
  {-# INLINE mempty #-}

  mappend = (<>)
  {-# INLINE mappend #-}

  mconcat = TransferM . mapM_ unTransferM
  {-# INLINE mconcat #-}

-- | A action that transfers bytes from its input pointer. Transfer
-- could either be writing or reading.
type TransferAction t = Ptr Word8 -> TransferM t

instance LAction (BYTES Int) (TransferAction t) where
  offset <.> action = action . (offset<.>)
  {-# INLINE (<.>) #-}

instance Distributive (BYTES Int) (TransferAction t)

-- | An element of type `Tranfer t m` is an action which when executed
-- transfers bytes /into/ or out of its input buffer.  The type
-- @`Transfer` t m@ forms a monoid and hence can be concatenated using
-- the `<>` operator.

type Transfer t = SemiR (TransferAction t) (BYTES Int)

-- | Returns the bytes that will be written when the write action is performed.
transferSize :: Transfer t -> BYTES Int
transferSize = semiRMonoid


-- | Make an explicit transfer action.
unsafeMakeTransfer :: LengthUnit u
                   => u                    -- ^ length of pointer accessed
                   -> (Ptr Word8 -> IO ()) -- ^ Pointer action to run
                   -> Transfer t
{-# INLINE unsafeMakeTransfer #-}
unsafeMakeTransfer sz action = SemiR (TransferM . action) $ inBytes sz


-- | This combinator runs an IO action which does not read/write any
-- bytes form the input buffer. This can be used to interleave some
-- side action in between the transfer.
unsafeInterleave :: IO a       -- ^
                 -> Transfer t
unsafeInterleave = unsafeMakeTransfer (0 :: BYTES Int) . const . void

-- | Perform the transfer without checking the bounds.
unsafeTransfer :: Pointer ptr
               => Transfer t
               -> ptr a       -- ^ The pointer to the buffer to/from which transfer occurs.
               -> IO ()
unsafeTransfer tr = transferIt . unsafeRawPtr
  where transferIt = unTransferM . semiRSpace tr . castPointer


------------------------  Read action ----------------------------

-- | The `ReadFrom` is the type that captures the act of reading from a
-- buffer and possibly doing some action on the bytes read. Although
-- inaccurate, it is helpful to think of elements of `ReadFromM` as action
-- that on an input buffer transfers data from it to some unspecified
-- source.
--
-- ReadFrom actions form a monoid with the following semantics: if @r1@
-- and @r2@ are two read actions then @r1 `<>` r2@ first reads the the
-- data associated with @r1@ and then reads the data associated with
-- @r2@.
type ReadFrom     = Transfer 'ReadFromBuffer



-- | The action @unsafeReadIntoPtr sz dptr@ gives a read action, which
-- if run on an input buffer, will transfers @sz@ bytes to the
-- destination pointer @dptr@. This action is unsafe because no checks
-- are done (or is it possible) to see if the destination pointer has
-- enough space to accommodate the bytes read.
unsafeReadIntoPtr :: (Pointer ptr, LengthUnit sz)
                  => sz               -- ^ how much to read.
                  -> Dest (ptr Word8) -- ^ buffer to read the bytes into
                  -> ReadFrom
unsafeReadIntoPtr sz dest = unsafeMakeTransfer sz
                            $ \ ptr -> memcpy dest (source ptr) sz

-- | The action @unsafeReadInto n dptr@ gives a read action which if
-- run on an input buffer, will transfers @n@ elements of type @a@
-- into the buffer pointed by @dptr@. Like @unsafeReadIntoPtr@ this
-- function does no checks on the destination pointer and hence is
-- unsafe.
unsafeReadInto :: EndianStore a
               => Int             -- ^ how many elements to read.
               -> Dest (Ptr a)    -- ^ buffer to read the elements into
               -> ReadFrom
unsafeReadInto n dest = unsafeMakeTransfer (sz dest)
                  $ \ ptr -> copyFromBytes dest (source ptr) n
  where sz  = (*) (toEnum n) . sizeOf . proxy
        proxy :: Dest (Ptr a) -> Proxy a
        proxy = const Proxy


-- | The `Write` is the type that captures the act of writing to a
-- buffer. Although inaccurate, it is helpful to think of elements of
-- `Write` as source of bytes of a fixed size.
--
-- Write actions form a monoid with the following semantics: if @w1@
-- and @w2@ are two write actions then @w1 `<>` w2@ first writes the
-- data associated from @w1@ and then the writes the data associated
-- with  @w2@.
type WriteTo     = Transfer 'WriteToBuffer



-- | Write many elements from the given buffer
unsafeWriteFrom :: EndianStore a => Int -> Src (Ptr a) -> WriteTo
unsafeWriteFrom n src = unsafeMakeTransfer (sz src)
                  $ \ ptr -> copyToBytes (destination ptr) src n
  where sz = (*) (toEnum n) . sizeOf . proxy
        proxy :: Src (Ptr a) -> Proxy a
        proxy = const Proxy



-- | The action @writeFromPtr sz sptr@ gives a write action, which if
-- run on an input buffer @buf@, will transfers @sz@ bytes from the
-- source pointer @sptr@ to the given buffer. Note that it is the
-- responsibility of the user to make sure that the input buffer @buf@
-- has enough space to receive @sz@ units of data if and when the read
-- action is executed.
--
unsafeWriteFromPtr ::(Pointer ptr, LengthUnit sz)
                   => sz
                   -> Src (ptr Word8)
                   -> WriteTo
unsafeWriteFromPtr sz src = unsafeMakeTransfer sz
                            $ \ ptr -> memcpy (destination ptr) src sz



instance IsString WriteTo where
  fromString = writeByteString . fromString

instance Encodable WriteTo where
  {-# INLINE toByteString #-}
  toByteString w  = unsafeCreate n $ unsafeTransfer w
    where BYTES n = transferSize w

  {-# INLINE unsafeFromByteString #-}
  unsafeFromByteString = writeByteString

  {-# INLINE fromByteString #-}
  fromByteString       = Just . writeByteString



-- | Writes a strict bytestring.
writeByteString :: ByteString -> WriteTo
writeByteString bs = unsafeMakeTransfer (BU.length bs) $ BU.unsafeCopyToPointer bs
