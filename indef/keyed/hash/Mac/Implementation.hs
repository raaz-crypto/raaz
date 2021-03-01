{-# LANGUAGE ConstraintKinds             #-}
{-# LANGUAGE MultiParamTypeClasses       #-}
{-# LANGUAGE FlexibleInstances           #-}
{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE DataKinds                   #-}
{-# LANGUAGE FlexibleContexts            #-}
{-# LANGUAGE RecordWildCards             #-}
-- | An implementation for simple MAC which is based on a
-- cryptographic hash. This construction is safe only for certain
-- hashes like blake2 and therefore should not be used
-- indiscriminately. In particular, sha2 hashes should not be used in
-- this mode as they are prone to length extension attack.
--
-- If you want to use sha2 hashs for message authentication, you
-- should make use of the more complicated HMAC construction.
--
module Mac.Implementation
          ( Prim
          , name
          , description
          , Internals
          , BufferAlignment
          , BufferPtr
          , processBlocks
          , processLast
          , additionalBlocks
          , Key (..)
          ) where

import           Data.ByteString       as BS
import           Raaz.Core
import           Raaz.Core.Transfer.Unsafe
import           Raaz.Primitive.Keyed.Internal
import qualified Implementation        as Base
import qualified Utils                 as U
import qualified Buffer                as B

type Prim = Keyed Base.Prim

-- | Name of the implementation.
name :: String
name = Base.name ++ "-keyed-hash"

-- | Description of the implementation.
description :: String
description = "Implementation of a MAC based on simple keyed hashing that makes use of "
              ++ Base.name
              ++ " implementation."

type BufferAlignment = Base.BufferAlignment
type BufferPtr       = AlignedBlockPtr BufferAlignment Prim

toKeyedBlocks :: BlockCount Base.Prim -> BlockCount Prim
toKeyedBlocks = toEnum . fromEnum

fromKeyedBlocks :: BlockCount Prim -> BlockCount Base.Prim
fromKeyedBlocks = toEnum . fromEnum

-- | The additional space required in the buffer for processing the data.
additionalBlocks :: BlockCount Prim
additionalBlocks = toKeyedBlocks Base.additionalBlocks

trim ::  Key (Keyed Base.Prim) -> BS.ByteString
trim (Key hKey) = BS.take sz hKey
  where sz = fromEnum $ sizeOf (Proxy :: Proxy Base.Prim)


-- | The internal memory used by the implementation.
data Internals = MACInternals { hashInternals    :: Base.Internals
                              , keyBuffer        :: B.Buffer 1
                              , atStart          :: MemoryCell Bool
                                -- Flag to check whether the key has been processed or not.
                                -- see the note on Delayed key processing
                              }

-- | Process the key inside the buffer with the process Buffer
-- function.
processKey :: Internals -> IO ()
processKey MACInternals{..} = U.processBuffer keyBuffer hashInternals


-- | Process the key in the buffer with the processLast function.
processKeyLast :: Internals -> IO ()
processKeyLast MACInternals{..} = Base.processLast bufPtr bufsz hashInternals
  where bufPtr = B.unsafeGetBufferPointer keyBuffer
        bufsz  = inBytes $ blocksOf 1 (Proxy :: Proxy Base.Prim)


instance Memory Internals where
  memoryAlloc = MACInternals <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . hashInternals

-- * Delayed key processing ::
--
-- It would look like the initialisation step is pretty straight
-- forward. Write the padded key to the buffer and then run process
-- blocks on it. This will work as long as the message that needs to
-- be authenticated is at-least 1 byte long.
--
-- For null bytes the padded key block is the last block and hashes
-- like blake2 pass a different finalisation flag for the last
-- block. At initialisation we cannot predict whether the message we
-- are about to see is empty or not. So we keep everything ready
-- (i.e. write the key into the keybuffer) and mark a flag that says
-- we are at the start of the message processing. The first time we
-- call processBlocks or processLast, will have to do the appropriate
-- initialisation and then proceed from there on.

instance Initialisable Internals (Key (Keyed Base.Prim)) where
  initialise hKey imem
    = do initialise hash0 $ hashInternals imem
         writeKeyIntoBuffer $ keyBuffer imem
         initialise True $ atStart imem
           where kbs        = trim hKey
                 hash0      :: Base.Prim
                 hash0      = hashInit $ Raaz.Core.length kbs
                 keyWrite   = padWrite 0 (blocksOf 1 proxyPrim) $ writeByteString kbs

                 writeKeyIntoBuffer = unsafeTransfer keyWrite . B.unsafeGetBufferPointer
                 proxyPrim = Proxy :: Proxy Base.Prim

instance Extractable Internals Prim where
  extract = fmap unsafeToKeyed . extract . hashInternals


-- | The function that process bytes in multiples of the block size of
-- the primitive.
processBlocks :: BufferPtr
              -> BlockCount Prim
              -> Internals
              -> IO ()
processBlocks aptr blks imem@MACInternals{..} = do
  start <- extract atStart
  when start $ do processKey imem
                  initialise False atStart
  Base.processBlocks (castPointer aptr) (fromKeyedBlocks blks) hashInternals

-- | Process the last bytes of the stream.
processLast :: BufferPtr
            -> BYTES Int
            -> Internals
            -> IO ()
processLast aptr sz imem@MACInternals{..} = do
  start <- extract atStart
  if start && sz == 0 then processKeyLast imem
    else do when start $ processKey imem
            Base.processLast (castPointer aptr) sz hashInternals
