{-# LANGUAGE DataKinds                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving       #-}
{-# LANGUAGE FlexibleInstances                #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE TypeFamilies                     #-}

-- | The internals of ChaCha20 ciphers. The variant of Chacha20 that
-- we implement is the IETF version described in RFC 7538 with 32-bit
-- (4-byte) counter and 96-bit (12-byte) IV.
module Raaz.Primitive.ChaCha20.Internal
       ( ChaCha20(..), WORD, Counter(..), IV(..), KEY(..), ChaCha20Mem(..)
       , keyCellPtr, ivCellPtr, counterCellPtr
       ) where

import Control.Applicative
import Control.Monad.Reader ( withReaderT   )
import Data.String
import Data.Word
import Foreign.Storable
import Foreign.Ptr                ( Ptr  )
import Prelude


import Raaz.Core

-- | The type associated with the ChaCha20 cipher.
data ChaCha20 = ChaCha20


-- | The word type
type WORD     = LE Word32

-- | The IV for the chacha20
newtype IV       = IV (Tuple 3 (LE Word32))     deriving (Storable, EndianStore)

instance Encodable IV

instance Show IV where
  show = showBase16

instance IsString IV where
  fromString = fromBase16

-- | The counter type for chacha20
newtype Counter  = Counter (LE Word32) deriving (Num, Enum, Storable, EndianStore, Show, Eq, Ord)


-- | The key type.
newtype KEY      = ChaCha20Key (Tuple 8 WORD) deriving (Storable, EndianStore)

instance Encodable KEY

instance Show KEY where
  show = showBase16

instance IsString KEY where
  fromString = fromBase16

instance Primitive ChaCha20 where
  type BlockSize ChaCha20      = 64

type instance Key ChaCha20            = (KEY, IV, Counter)



---------- Memory for ChaCha20 implementations  ------------------
-- | chacha20 memory
data ChaCha20Mem = ChaCha20Mem { keyCell      :: MemoryCell KEY
                               , ivCell       :: MemoryCell IV
                               , counterCell  :: MemoryCell Counter
                               }

keyCellPtr :: MT ChaCha20Mem (Ptr KEY)
keyCellPtr = withReaderT keyCell getCellPointer

ivCellPtr :: MT ChaCha20Mem (Ptr IV)
ivCellPtr = withReaderT ivCell getCellPointer

counterCellPtr :: MT ChaCha20Mem (Ptr Counter)
counterCellPtr = withReaderT counterCell getCellPointer

instance Memory ChaCha20Mem where
  memoryAlloc     = ChaCha20Mem <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . keyCell

instance Initialisable ChaCha20Mem (KEY, IV, Counter) where
  initialise (k,iv,ctr) = do withReaderT keyCell     $ initialise k
                             withReaderT ivCell      $ initialise iv
                             withReaderT counterCell $ initialise ctr


instance Initialisable ChaCha20Mem (KEY, IV) where
  initialise (k, iv) = initialise (k, iv, 0 :: Counter)

instance Extractable ChaCha20Mem () where
  extract = return ()
