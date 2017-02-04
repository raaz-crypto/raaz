{-# LANGUAGE ForeignFunctionInterface         #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE FlexibleInstances                #-}
{-# LANGUAGE DataKinds                        #-}

module Raaz.Cipher.ChaCha20.Implementation.CPortable
       ( implementation, chacha20Random
       ) where

import Control.Monad.IO.Class   ( liftIO )
import Foreign.Ptr              ( Ptr    )

import Raaz.Core
import Raaz.Cipher.Internal
import Raaz.Cipher.ChaCha20.Internal

implementation :: SomeCipherI ChaCha20
implementation  = SomeCipherI chacha20Portable

-- | Chacha20 block transformation.
foreign import ccall unsafe
  "raaz/cipher/chacha20/cportable.h raazChaCha20Block"
  c_chacha20_block :: Pointer      -- Message
                   -> Int          -- number of blocks
                   -> Ptr KEY      -- key
                   -> Ptr IV       -- iv
                   -> Ptr Counter  -- Counter value
                   -> IO ()




-- | Encrypting/Decrypting a block of chacha20.
chacha20Block :: Pointer -> BLOCKS ChaCha20 -> MT ChaCha20Mem ()
chacha20Block msgPtr nblocks = do keyPtr <- onSubMemory keyCell     getCellPointer
                                  ivPtr  <- onSubMemory ivCell      getCellPointer
                                  ctrPtr <- onSubMemory counterCell getCellPointer
                                  liftIO $ c_chacha20_block msgPtr (fromEnum nblocks) keyPtr ivPtr ctrPtr

-- | The chacha20 randomness generator.
chacha20Random :: Pointer -> BLOCKS ChaCha20 -> MT ChaCha20Mem ()
chacha20Random = chacha20Block

chacha20Portable :: CipherI ChaCha20 ChaCha20Mem ChaCha20Mem
chacha20Portable = makeCipherI
                   "chacha20-cportable"
                   "Implementation of the chacha20 stream cipher (RFC7539)"
                   chacha20Block
                   wordAlignment
