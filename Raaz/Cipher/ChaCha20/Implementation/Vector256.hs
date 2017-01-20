{-# LANGUAGE ForeignFunctionInterface         #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE FlexibleInstances                #-}
{-# LANGUAGE DataKinds                        #-}

module Raaz.Cipher.ChaCha20.Implementation.Vector256
       ( implementation, RandomBlock, chacha20Random
       ) where

import Control.Monad.IO.Class   ( liftIO )
import Foreign.Ptr              ( Ptr    )
import Raaz.Core
import Raaz.Cipher.Internal
import Raaz.Cipher.ChaCha20.Internal


implementation :: SomeCipherI ChaCha20
implementation  = SomeCipherI chacha20Vector

-- | Chacha20 block transformation.
foreign import ccall unsafe
  "raazChaCha20BlockVector256"
  c_chacha20_block :: Pointer      -- Message
                   -> Int          -- number of blocks
                   -> Ptr KEY      -- key
                   -> Ptr IV       -- iv
                   -> Ptr Counter  -- Counter value
                   -> IO ()


chacha20Block :: Pointer -> BLOCKS ChaCha20 -> MT ChaCha20Mem ()
chacha20Block msgPtr nblocks = do keyPtr <- onSubMemory keyCell     getCellPointer
                                  ivPtr  <- onSubMemory ivCell      getCellPointer
                                  ctrPtr <- onSubMemory counterCell getCellPointer
                                  liftIO $ c_chacha20_block msgPtr (fromEnum nblocks) keyPtr ivPtr ctrPtr

chacha20Vector :: CipherI ChaCha20 ChaCha20Mem ChaCha20Mem
chacha20Vector = makeCipherI
                 "chacha20-vector-256"
                 "Implementation of the chacha20 stream cipher using the gcc's 256-bit vector instructions"
                 chacha20Block
                 32

-------------------------------- Chacha20 PRG that used vector implementation ------------

-- | The type capturing the random block that will be generated.
type RandomBlock = Aligned 32 (Tuple 32 WORD)

-- | Chacha20 prg in portable-C transformation.
foreign import ccall unsafe
  "raaz/cipher/chacha20/cportable.h raazChaCha20Random"
  c_chacha20_random :: Pointer     -- Message
                   -> Ptr KEY      -- key
                   -> Ptr IV       -- iv
                   -> Ptr Counter  -- Counter value
                   -> IO ()

-- | The prg based on chacha20 stream cipher.
chacha20Random :: Pointer -> MT ChaCha20Mem ()
chacha20Random buf = do keyPtr <- onSubMemory keyCell     getCellPointer
                        ivPtr  <- onSubMemory ivCell      getCellPointer
                        ctrPtr <- onSubMemory counterCell getCellPointer
                        liftIO $ c_chacha20_random buf keyPtr ivPtr ctrPtr
