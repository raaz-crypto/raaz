{-# LANGUAGE DataKinds                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving       #-}
{-# LANGUAGE FlexibleInstances                #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE TypeFamilies                     #-}

-- | The internals of ChaCha20 ciphers. The variant of Chacha20 that
-- we implement is the IETF version described in RFC 7538 with 32-bit
-- (4-byte) counter and 96-bit (12-byte) IV.
module Raaz.Primitive.ChaCha20.Internal
       ( ChaCha20(..), XChaCha20(..)
       , WORD
       , Key(..), Nounce(..), Counter(..)
       , ChaCha20Mem(..)
       , keyCellPtr, ivCellPtr, counterCellPtr
       ) where

import Control.Monad.Reader ( withReaderT   )
import Foreign.Storable
import Foreign.Ptr                ( Ptr  )

import Raaz.Core


-- | The type associated with the ChaCha20 cipher.
data ChaCha20 = ChaCha20

-- | The type associated with the XChaCha20 variant.
data XChaCha20 = XChaCha20


instance Primitive ChaCha20 where
  type BlockSize ChaCha20      = 64

instance Primitive XChaCha20 where
  type BlockSize XChaCha20     = 64

-- | The word type
type WORD     = LE Word32
type KEY      = Tuple 8 WORD

newtype instance Key     ChaCha20 = Key     KEY
  deriving (Storable, EndianStore)
newtype instance Nounce  ChaCha20 = Nounce  (Tuple 3 WORD)
  deriving (Storable, EndianStore)

newtype instance Counter ChaCha20 = Counter WORD
  deriving (Num, Enum, Storable, EndianStore, Show, Eq, Ord)

instance Encodable (Key     ChaCha20)
instance Encodable (Nounce  ChaCha20)

instance Show (Key ChaCha20) where
  show = showBase16

instance Show (Nounce ChaCha20) where
  show = showBase16


instance IsString (Key ChaCha20) where
  fromString = fromBase16


instance IsString (Nounce ChaCha20) where
  fromString = fromBase16


newtype instance Key     XChaCha20 = XKey     KEY
  deriving (Storable, EndianStore)
newtype instance Nounce  XChaCha20 = XNounce  (Tuple 6 WORD)
  deriving (Storable, EndianStore)
newtype instance Counter XChaCha20 = XCounter WORD
  deriving (Num, Enum, Storable, EndianStore, Show, Eq, Ord)


instance Encodable (Key     XChaCha20)
instance Encodable (Nounce  XChaCha20)

instance Show (Key XChaCha20) where
  show = showBase16

instance Show (Nounce XChaCha20) where
  show = showBase16


instance IsString (Key XChaCha20) where
  fromString = fromBase16


instance IsString (Nounce XChaCha20) where
  fromString = fromBase16

---------- Memory for ChaCha20 implementations  ------------------
-- | chacha20 memory
data ChaCha20Mem = ChaCha20Mem { keyCell      :: MemoryCell (Key     ChaCha20)
                               , ivCell       :: MemoryCell (Nounce  ChaCha20)
                               , counterCell  :: MemoryCell (Counter ChaCha20)
                               }

keyCellPtr :: MT ChaCha20Mem (Ptr (Key ChaCha20))
keyCellPtr = withReaderT keyCell getCellPointer

ivCellPtr :: MT ChaCha20Mem (Ptr (Nounce ChaCha20))
ivCellPtr = withReaderT ivCell getCellPointer

counterCellPtr :: MT ChaCha20Mem (Ptr (Counter ChaCha20))
counterCellPtr = withReaderT counterCell getCellPointer

instance Memory ChaCha20Mem where
  memoryAlloc     = ChaCha20Mem <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . keyCell

instance Initialisable ChaCha20Mem (Key ChaCha20) where
  initialise  = withReaderT keyCell . initialise

instance Initialisable ChaCha20Mem (Nounce ChaCha20)  where
  initialise  = withReaderT ivCell . initialise

instance Initialisable ChaCha20Mem (Counter ChaCha20) where
  initialise = withReaderT counterCell . initialise

-- | Initialises key from a buffer. Use this instance if you want to
-- initialise (only the) key from a secure memory location.
instance InitialisableFromBuffer ChaCha20Mem where
  initialiser = liftTransfer (withReaderT keyCell) . initialiser . keyCell
