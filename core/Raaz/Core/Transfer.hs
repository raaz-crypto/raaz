{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE KindSignatures             #-}
-- |
--
-- Module      : Raaz.Core.Transfer
-- Description : Type safe transfer of bytes.
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--

module Raaz.Core.Transfer
       ( -- * Transfer actions.
         -- $transfer$
         Transfer, ReadFrom, WriteTo
       , consume, consumeStorable, consumeParse
       , writeEncodable
       , write, writeStorable, writeVector, writeStorableVector
       , writeBytes
       , padWrite, prependWrite, glueWrites
       , writeByteString
       , transferSize
       , skip
       ) where


import qualified Data.Vector.Generic       as G
import           Foreign.Storable          ( Storable, poke )

import           Raaz.Core.Transfer.Unsafe
import           Raaz.Core.Prelude
import           Raaz.Core.Parse.Unsafe
import           Raaz.Core.Parse     hiding (skip)
import           Raaz.Core.Types.Endian
import           Raaz.Core.Types.Pointer
import           Raaz.Core.Encode


-- | The transfer @skip l@ skip ahead by an offset @l@. If it is a
-- read, it does not read the next @l@ positions. If it is a write it
-- does not mutate the next @l@ positions.
skip :: LengthUnit l => l -> Transfer t
skip = flip unsafeMakeTransfer doNothing
       where doNothing = const $ return ()


-------------------------- Monoids for consuming stuff ------------------------------------

-- | Given a parser @p :: Parser a@ for parsing @a@ and @act :: a -> m
-- b@ consuming a, @consumeParse p act@, gives a reader that parses a
-- from the input buffer passing it to the action act.
consumeParse ::  Parser a -> (a -> IO b) -> ReadFrom
consumeParse p action = unsafeMakeTransfer (parseWidth p) $
                        unsafeRunParser p >=> void . action

-- | Reads @a@ from the buffer and supplies it to the action. The
-- value read is independent of the endianness of the underlying.
consume :: EndianStore a
        => (a -> IO b)
        -> ReadFrom
consume = consumeParse parse

-- | Similar to @consume@ but does not take care of adjusting for
-- endianness. Use therefore limited to internal buffers.
consumeStorable :: Storable a
                => (a -> IO b)
                -> ReadFrom
consumeStorable = consumeParse parseStorable

-------------------------- Monoid for writing stuff --------------------------------------

-- | The expression @`writeStorable` a@ gives a write action that
-- stores a value @a@ in machine endian. The type of the value @a@ has
-- to be an instance of `Storable`. This should be used when we want
-- to talk with C functions and not when talking to the outside world
-- (otherwise this could lead to endian confusion). To take care of
-- endianness use the `write` combinator.
writeStorable :: Storable a => a -> WriteTo
writeStorable a = unsafeMakeTransfer (sizeOf $ pure a) pokeIt
  where pokeIt = flip poke a . castPointer
-- | The expression @`write` a@ gives a write action that stores a
-- value @a@. One needs the type of the value @a@ to be an instance of
-- `EndianStore`. Proper endian conversion is done irrespective of
-- what the machine endianness is. The man use of this write is to
-- serialize data for the consumption of the outside world.
write :: EndianStore a => a -> WriteTo
write a = unsafeMakeTransfer (sizeOf $ pure a) $ flip (store . castPointer) a


-- | Write any encodable elements
writeEncodable :: Encodable a => a -> WriteTo
writeEncodable = writeByteString . toByteString

-- | The vector version of `writeStorable`.
writeStorableVector :: (Storable a, G.Vector v a) => v a -> WriteTo
{-# INLINE writeStorableVector #-}
writeStorableVector = G.foldl' foldFunc mempty
  where foldFunc w a =  w <> writeStorable a

{-

TODO: This function can be slow due to the fact that each time we use
the semi-direct product, we incur a cost due to the lambda being not
lifted.

-}

-- | The vector version of `write`.
writeVector :: (EndianStore a, G.Vector v a) => v a -> WriteTo
{-# INLINE writeVector #-}
{- TODO: improve this using the fact that the size is known -}
writeVector = G.foldl' foldFunc mempty
  where foldFunc w a =  w <> write a
{- TODO: Same as in writeStorableVector -}


-- | The combinator @writeBytes b n@ writes @b@ as the next @n@
-- consecutive bytes.
writeBytes :: LengthUnit n
           => Word8   -- ^ Byte to write
           -> n       -- ^ How much to write
           -> WriteTo
writeBytes w8 n = unsafeMakeTransfer n memsetIt
  where memsetIt cptr = memset cptr w8 n

-- | The combinator @glueWrites w n hdr ftr@ is equivalent to @hdr <>
-- glue <> ftr@ where the write @glue@ writes just enough bytes @w@ so
-- that the total length is aligned to the boundary @n@.
glueWrites :: LengthUnit n
           => Word8    -- ^ The bytes to use in the glue
           -> n        -- ^ The length boundary to align to.
           -> WriteTo  -- ^ The header write
           -> WriteTo  -- ^ The footer write
           -> WriteTo
glueWrites w8 n hdr ftr = hdr <> writeBytes w8 lglue <> ftr
  where lhead   = transferSize hdr
        lfoot   = transferSize ftr
        lexceed = (lhead + lfoot) `rem` nBytes  -- bytes exceeding the boundary.
        lglue   = if lexceed > 0 then nBytes - lexceed else 0
        nBytes  = inBytes n

-- | The write action @prependWrite w n wr@ is wr pre-pended with the byte @w@ so that the total length
-- ends at a multiple of @n@.
prependWrite  :: LengthUnit n
              => Word8     -- ^ the byte to pre-pend with.
              -> n         -- ^ the length to align the message to
              -> WriteTo  -- ^ the message that needs pre-pending
              -> WriteTo
prependWrite w8 n = glueWrites w8 n mempty

-- | The write action @padWrite w n wr@ is wr padded with the byte @w@ so that the total length
-- ends at a multiple of @n@.
padWrite :: LengthUnit n
         => Word8     -- ^ the padding byte to use
         -> n         -- ^ the length to align message to
         -> WriteTo   -- ^ the message that needs padding
         -> WriteTo
padWrite w8 n = flip (glueWrites w8 n) mempty


-------------  Reading stuff  -----------------------------------
