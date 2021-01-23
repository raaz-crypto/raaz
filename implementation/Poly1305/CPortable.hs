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

import Raaz.Core
import Raaz.Core.Transfer.Unsafe
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
              -> Internals
              -> IO ()
processBlocks buf blks = withAccumR $ runWithBlocks verse_poly1305_c_portable_incremental buf blks

-- | Process a message that is exactly a multiple of the blocks.
blocksMac :: BufferPtr
          -> BlockCount Poly1305
          -> Internals
          -> IO ()
blocksMac buf blks = withAccumRS $ runWithBlocks verse_poly1305_c_portable_blockmac buf blks

-- | Run an IO action with the pointers to the element, r and s cells.
withAccumRS :: ( Ptr Element ->
                 Ptr (Tuple 2 Word64) ->
                 Ptr (Tuple 2 Word64) ->
                 a
               )
            -> Internals
            -> a
withAccumRS func mem = withAccumR func mem $ sKeyPtr mem

withAccumR :: ( Ptr Element ->
                Ptr (Tuple 2 Word64) ->
                a
              )
           -> Internals
           -> a
withAccumR func mem = func (accumPtr mem) $ rKeyPtr mem

runWithBlocks :: ( Ptr a ->
                   Word64 ->
                   b
                 )
              -> BufferPtr
              -> BlockCount Poly1305
              -> b
runWithBlocks func buf = unsafeWithPointerCast func buf . toEnum . fromEnum

-- | Process a message that has its last block incomplete. The total
-- blocks argument here is the greatest multiple of the block that is
-- less that the message length.
partialBlockMac :: BufferPtr
                -> BlockCount Poly1305
                -> Internals
                -> IO ()
partialBlockMac buf blks mem = do
  processBlocks buf blks mem
  withAccumRS (unsafeWithPointerCast partialMac buf) mem
  where partialMac bufPtr = verse_poly1305_c_portable_partialmac (bufPtr `movePtr` blks)

-- | Process the last bytes.
processLast :: BufferPtr
            -> BYTES Int
            -> Internals
            -> IO ()
processLast buf nBytes mem
  | blksC == blksF = blocksMac buf blksC mem
  | otherwise      = do
      unsafeTransfer pad (forgetAlignment buf)
      partialBlockMac buf blksF mem
  where blksC = atLeast nBytes :: BlockCount Poly1305
        blksF = atMost  nBytes :: BlockCount Poly1305
        pad   = padding nBytes

-- | Poly1305 padding. Call this padding function if and only if the
-- message is not a multiple of the block length.
padding :: BYTES Int    -- Data in buffer.
        -> WriteTo
padding mLen = padWrite 0 boundary $ skip mLen `mappend` one
  where one         = writeStorable (1::Word8)
        boundary    = blocksOf 1 (Proxy :: Proxy Poly1305)
