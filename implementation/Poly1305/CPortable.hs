{-# LANGUAGE DataKinds                  #-}

-- | The portable C-implementation of Poly1305.
module Poly1305.CPortable
       ( name, description
       , Prim, Internals, BufferAlignment
       , BufferPtr
       , additionalBlocks
       , processBlocks
       , processLast
       ) where

import Foreign.Ptr                ( castPtr, Ptr  )
import Control.Monad.IO.Class     ( liftIO        )

import Raaz.Core
import Raaz.Primitive.Poly1305.Internal
import Poly1305.Memory

import Raaz.Verse.Poly1305.C.Portable

name :: String
name = "poly1305-libverse-c"

description :: String
description = "Poly1305 Implementation in C exposed by libverse"

type Prim                    = Poly1305
type Internals               = Mem
type BufferAlignment         = 32
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

additionalBlocks :: BlockCount Poly1305
additionalBlocks = blocksOf 1 Proxy

-- | Incrementally process poly1305 blocks.
processBlocks :: BufferPtr
              -> BlockCount Poly1305
              -> MT Internals ()
processBlocks buf blks = do
  aP <- accumPtr
  rP <- rKeyPtr
  liftIO $ verse_poly1305_c_portable_incremental bufPtr wBlks aP rP
  where bufPtr = castPtr $ forgetAlignment buf
        wBlks  = toEnum $ fromEnum blks

-- | Process a message that is exactly a multiple of the blocks.
blocksMac :: BufferPtr
          -> BlockCount Poly1305
          -> MT Internals ()
blocksMac buf blks = runWithRS $ verse_poly1305_c_portable_blockmac bufPtr wBlks
  where bufPtr = castPtr $ forgetAlignment buf
        wBlks  = toEnum  $ fromEnum blks

-- | Run an IO action with the pointers to the element, r and s cells.
runWithRS :: ( Ptr Element ->
               Ptr (Tuple 2 Word64) ->
               Ptr (Tuple 2 Word64) ->
               IO ()
             )
          -> MT Internals ()
runWithRS func = do aP <- accumPtr
                    rP <- rKeyPtr
                    sKeyPtr >>= liftIO . func aP rP


-- | Process a message that has its last block incomplete. The total
-- blocks argument here is the greatest multiple of the block that is
-- less that the message length.
partialBlockMac :: BufferPtr
                -> BlockCount Poly1305
                -> MT Internals ()
partialBlockMac buf blks = do
  processBlocks buf blks
  runWithRS $ verse_poly1305_c_portable_partialmac lastBlockPtr
  where bufPtr       = castPtr $ forgetAlignment buf
        lastBlockPtr = bufPtr `movePtr` blks


-- | Process the last bytes.
processLast :: BufferPtr
            -> BYTES Int
            -> MT Internals ()
processLast buf nBytes
  | blksC == blksF = blocksMac buf blksC
  | otherwise      = do
      unsafeTransfer pad (forgetAlignment buf)
      partialBlockMac buf blksF
  where blksC = atLeast nBytes :: BlockCount Poly1305
        blksF = atMost  nBytes :: BlockCount Poly1305
        pad   = padding nBytes

-- | Poly1305 padding. Call this padding function if and only if the
-- message is not a multiple of the block length.
padding :: BYTES Int    -- Data in buffer.
        -> WriteM (MT Internals)
padding mLen = padWrite 0 boundary $ skip mLen `mappend` one
  where one         = writeStorable (1::Word8)
        boundary    = blocksOf 1 (Proxy :: Proxy Poly1305)
