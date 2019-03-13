{-# LANGUAGE ConstraintKinds             #-}
{-# LANGUAGE MultiParamTypeClasses       #-}
{-# LANGUAGE FlexibleInstances           #-}
{-# LANGUAGE TypeFamilies                #-}
{-# LANGUAGE DataKinds                   #-}
{-# LANGUAGE FlexibleContexts            #-}

-- | An implementation for simple MAC which is based on a
-- cryptographic hash. This construction is safe only for safe for
-- certain hashes like blake2 and therefore should not be used
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
          , processBlocks
          , processLast
          , additionalBlocks
          ) where

import           Control.Monad.Reader
import           Data.Proxy
import           Raaz.Core
import           Raaz.Primitive.Keyed.Internal

import qualified Implementation        as Base
import qualified Utils                 as U

type Prim = Keyed Base.Prim

-- | Name of the implementation.
name :: String
name = Base.name ++ "-keyed-hash"

-- | Description of the implementation.
description :: String
description = "This is the implementation of a MAC using a simple keyed hashing using the " ++ Base.name
              ++ "implementation."

type BufferAlignment = Base.BufferAlignment

toKeyedBlocks :: BLOCKS Base.Prim -> BLOCKS Prim
toKeyedBlocks = toEnum . fromEnum

fromKeyedBlocks :: BLOCKS Prim -> BLOCKS Base.Prim
fromKeyedBlocks = toEnum . fromEnum

-- | The additional space required in the buffer for processing the data.
additionalBlocks :: BLOCKS Prim
additionalBlocks = toKeyedBlocks Base.additionalBlocks



-- | The internal memory used by the implementation.
data Internals = MACInternals { hashInternals :: Base.Internals
                              , keyBuffer     :: U.Buffer 1
                              }


instance Memory Internals where
  memoryAlloc = MACInternals <$> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . hashInternals

instance Initialisable Internals (HashKey Base.Prim) where
  initialise hKey = do withReaderT hashInternals $ initialise hash0
                       bufPtr <- U.getBufferPointer <$> withReaderT keyBuffer ask
                       unsafeTransfer keyWrite $ forgetAlignment bufPtr
                       processKey
     where hash0    :: Base.Prim
           hash0    = hashInit $ Raaz.Core.length kbs
           kbs      = trim (Proxy :: Proxy Base.Prim) hKey
           keyWrite = padWrite 0 (blocksOf 1 proxyPrim) $ writeByteString kbs
           processKey = withReaderT keyBuffer ask >>= withReaderT hashInternals . U.processBuffer
           proxyPrim = Proxy :: Proxy Base.Prim

instance Extractable Internals Prim where
  extract = unsafeToKeyed <$> withReaderT hashInternals extractIt
    where extractIt :: MT Base.Internals Base.Prim
          extractIt = extract


-- | The function that process bytes in multiples of the block size of
-- the primitive.
processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS Prim
              -> MT Internals ()
processBlocks aptr = withReaderT hashInternals  . Base.processBlocks aptr . fromKeyedBlocks

-- | Process the last bytes of the stream.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast aptr = withReaderT hashInternals . Base.processLast aptr
