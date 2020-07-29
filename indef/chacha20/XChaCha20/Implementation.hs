{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}

module XChaCha20.Implementation where

import           Raaz.Core
import           Raaz.Primitive.ChaCha20.Internal


import qualified Implementation as Base

name :: String
name = "x" ++ Base.name

description :: String
description = Base.description ++ " This is the XChaCha variant."

type Prim                    = XChaCha20
data Internals               = XChaCha20Mem
  { copyOfKey         :: MemoryCell (Key ChaCha20)
  , chacha20Internals :: Base.Internals
  }

type BufferAlignment         = Base.BufferAlignment
type BufferPtr               = AlignedBlockPtr BufferAlignment Prim

instance Memory Internals where
  memoryAlloc     = XChaCha20Mem <$> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . copyOfKey


instance Initialisable Internals (Key XChaCha20) where
  initialise xkey = initialise xkey . copyOfKey

instance Initialisable Internals (Nounce XChaCha20) where
  initialise xnounce imem = do
    let dest = destination $ chacha20Internals imem
        src  = source $ copyOfKey imem
      in Base.copyKey dest src
    Base.xchacha20Setup xnounce $ chacha20Internals imem

instance Initialisable Internals (BlockCount XChaCha20) where
  initialise bcount = initialise bcountP . chacha20Internals
    where bcountP :: BlockCount ChaCha20
          bcountP = toEnum $ fromEnum bcount

instance Extractable Internals (BlockCount XChaCha20) where
  extract = fmap coerce . extract . chacha20Internals
    where coerce :: BlockCount ChaCha20 -> BlockCount XChaCha20
          coerce = toEnum . fromEnum

additionalBlocks :: BlockCount XChaCha20
additionalBlocks = coerce Base.additionalBlocks
    where coerce :: BlockCount Base.Prim -> BlockCount XChaCha20
          coerce = toEnum . fromEnum


processBlocks :: BufferPtr
              -> BlockCount Prim
              -> Internals
              -> IO ()
processBlocks buf bcount =
  Base.processBlocks (castPointer buf) (coerce bcount) . chacha20Internals
  where coerce :: BlockCount XChaCha20 -> BlockCount Base.Prim
        coerce = toEnum . fromEnum

-- | Process the last bytes.
processLast :: BufferPtr
            -> BYTES Int
            -> Internals
            -> IO ()
processLast buf nbytes = Base.processLast (castPointer buf) nbytes . chacha20Internals
