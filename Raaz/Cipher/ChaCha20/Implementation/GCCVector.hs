{-# LANGUAGE ForeignFunctionInterface         #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE FlexibleInstances                #-}

module Raaz.Cipher.ChaCha20.Implementation.GCCVector
       ( implementation
       ) where

import Control.Monad.IO.Class   ( liftIO )

import Raaz.Core
import Raaz.Cipher.Internal
import Raaz.Cipher.ChaCha20.Internal

implementation :: SomeCipherI ChaCha20
implementation  = SomeCipherI chacha20Vector

-- | Chacha20 block transformation.
foreign import ccall unsafe
  "raaz/cipher/chacha20/vector.h raazChaCha20BlockVector"
  c_chacha20_block :: Pointer  -- Message
                   -> Int      -- number of blocks
                   -> Pointer  -- key
                   -> Pointer  -- iv
                   -> Pointer  -- Counter value
                   -> IO ()

chacha20Block :: Pointer -> BLOCKS ChaCha20 -> MT ChaCha20Mem ()
chacha20Block msgPtr nblocks = do keyPtr <- onSubMemory keyCell     getMemoryPointer
                                  ivPtr  <- onSubMemory ivCell      getMemoryPointer
                                  ctrPtr <- onSubMemory counterCell getMemoryPointer
                                  liftIO $ c_chacha20_block msgPtr (fromEnum nblocks) keyPtr ivPtr ctrPtr

chacha20Vector :: CipherI ChaCha20 ChaCha20Mem ChaCha20Mem
chacha20Vector = makeCipherI
                   "chacha20-gccvector"
                   "Implementation of the chacha20 stream cipher using the gcc's vector instructions"
                   chacha20Block
                   $ inBytes (1 :: ALIGN) -- ^ TODO improve on this.
