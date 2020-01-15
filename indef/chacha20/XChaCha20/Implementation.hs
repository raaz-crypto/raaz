{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE TypeSynonymInstances       #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}

module XChaCha20.Implementation where



import           Control.Monad.Reader       ( withReaderT, ask )
import           Control.Monad.IO.Class     ( liftIO       )

import           Raaz.Core
import           Raaz.Primitive.ChaCha20.Internal


import qualified Implementation as Base

name :: String
name = "x" ++ Base.name

description :: String
description = Base.description ++ " This is the XChaCha variant."

type Prim                    = XChaCha20
data Internals               = XChaCha20Mem
  { copyOfKey         ::  MemoryCell (Key ChaCha20)
  , chacha20Internals :: Base.Internals
  }

type BufferAlignment         = Base.BufferAlignment

instance Memory Internals where
  memoryAlloc     = XChaCha20Mem <$> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . copyOfKey


instance Initialisable Internals (Key XChaCha20) where
  initialise xkey = withReaderT copyOfKey $ initialise xkey

instance Initialisable Internals (Nounce XChaCha20) where
  initialise xnounce = do internals  <- ask
                          let dest = destination $ chacha20Internals internals
                              src  = source $ copyOfKey internals
                            in do liftIO $ Base.copyKey dest src
                          withReaderT chacha20Internals $ Base.xchacha20Setup xnounce

instance Initialisable Internals (BLOCKS XChaCha20) where
  initialise = withReaderT chacha20Internals . initialise . coerce
    where coerce :: BLOCKS XChaCha20 -> BLOCKS ChaCha20
          coerce = toEnum . fromEnum

instance Extractable Internals (BLOCKS XChaCha20) where
  extract = coerce <$> withReaderT chacha20Internals extract
    where coerce :: BLOCKS ChaCha20 -> BLOCKS XChaCha20
          coerce = toEnum . fromEnum

additionalBlocks :: BLOCKS XChaCha20
additionalBlocks = coerce Base.additionalBlocks
    where coerce :: BLOCKS Base.Prim -> BLOCKS XChaCha20
          coerce = toEnum . fromEnum


processBlocks :: AlignedPointer BufferAlignment
              -> BLOCKS Prim
              -> MT Internals ()
processBlocks buf = withReaderT chacha20Internals . Base.processBlocks buf . coerce
  where coerce :: BLOCKS XChaCha20 -> BLOCKS Base.Prim
        coerce = toEnum . fromEnum

-- | Process the last bytes.
processLast :: AlignedPointer BufferAlignment
            -> BYTES Int
            -> MT Internals ()
processLast buf = withReaderT chacha20Internals . Base.processLast buf
