{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Poly1305.
module Poly1305.CPortable
       ( name, description
       , Prim, Internals, BufferAlignment
       , additionalBlocks
       , processBlocks
       , processLast
       , clamp
       ) where

import Foreign.Ptr                ( castPtr, Ptr  )
import Control.Monad.IO.Class     ( liftIO        )
import Control.Monad.Reader       ( withReaderT   )
import Data.Word
import Data.Proxy

import Raaz.Core
import Raaz.Primitive.Poly1305.Internal
import Raaz.Primitive.Poly1305.Memory

import Raaz.Verse.Poly1305.C.Portable

name :: String
name = "poly1305-libverse-c"

description :: String
description = "Poly1305 Implementation in C exposed by libverse"

type Prim                    = Poly1305
type Internals               = Mem
type BufferAlignment         = 32


additionalBlocks :: BLOCKS Poly1305
additionalBlocks = blocksOf 1 Proxy

-- | Get the pointer to the accumulator array.
accumPtr :: MT Internals (Ptr Element)
accumPtr = withReaderT accCell getCellPointer

-- | Get the pointer to the array holding the key fragment r.
rKeyPtr  :: MT Internals  (Ptr (Tuple 2 Word64))
rKeyPtr  = castPtr  <$> withReaderT rCell getCellPointer

-- | Get the pointer to the array holding the key fragment s.
sKeyPtr  :: MT Internals (Ptr (Tuple 2 Word64))
sKeyPtr  = castPtr <$> withReaderT sCell getCellPointer

-- | Incrementally process poly1305 blocks.
processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS Poly1305
              -> MT Internals ()
processBlocks buf blks = do
  aP <- accumPtr
  rP <- rKeyPtr
  liftIO $ verse_poly1305_c_portable_incremental bufPtr wBlks aP rP
  where bufPtr = castPtr $ forgetAlignment buf
        wBlks  = toEnum $ fromEnum blks

-- | Process a message that is exactly a multiple of the blocks.
blocksMac :: AlignedPointer BufferAlignment
          -> BLOCKS Poly1305
          -> MT Internals ()
blocksMac buf blks = do
  aP <- accumPtr
  rP <- rKeyPtr
  sP <- sKeyPtr
  liftIO $ verse_poly1305_c_portable_blockmac bufPtr wBlks aP rP sP
  where bufPtr = castPtr $ forgetAlignment buf
        wBlks  = toEnum $ fromEnum blks

-- | Process a message that has its last block incomplete. The total
-- blocks argument here is the greatest multiple of the block that is
-- less that the message length.
partialBlockMac :: AlignedPointer BufferAlignment
                -> BLOCKS Poly1305
                -> MT Internals ()
partialBlockMac buf blks = do
  processBlocks buf blks
  aP <- accumPtr
  rP <- rKeyPtr
  sP <- sKeyPtr
  let bufPtr = castPtr $ forgetAlignment buf
      lastBlockPtr = bufPtr `movePtr` blks
      in liftIO $ verse_poly1305_c_portable_partialmac lastBlockPtr aP rP sP

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast buf nBytes
  | blksC == blksF = blocksMac buf blksC
  | otherwise      = do
      unsafeTransfer pad (forgetAlignment buf)
      partialBlockMac buf blksF
  where blksC = atLeast nBytes :: BLOCKS Poly1305
        blksF = atMost  nBytes :: BLOCKS Poly1305
        pad   = padding nBytes

-- | Poly1305 padding. Call this padding function if and only if the
-- message is not a multiple of the block length.
padding :: BYTES Int    -- Data in buffer.
        -> WriteM (MT Internals)
padding mLen = padWrite 0 boundary $ skip mLen `mappend` one
  where one         = writeStorable (1::Word8)
        boundary    = blocksOf 1 (Proxy :: Proxy Poly1305)

-- | The clamping operation
clamp :: MT Internals ()
clamp = rKeyPtr >>= liftIO . flip verse_poly1305_c_portable_clamp 1
