{-# LANGUAGE DataKinds                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving       #-}
{-# LANGUAGE FlexibleInstances                #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE TypeFamilies                     #-}

{- HLINT ignore "Unused LANGUAGE pragma" -}

-- | The internals of ChaCha20 ciphers. The variant of Chacha20 that
-- we implement is the IETF version described in RFC 7538 with 32-bit
-- (4-byte) counter and 96-bit (12-byte) IV.
module Raaz.Primitive.ChaCha20.Internal
       ( ChaCha20(..), XChaCha20(..)
       , Key(..), Nounce(..)
       , ChaCha20Mem(..)
       , keyCellPtr, ivCellPtr, counterCellPtr
       ) where

import Foreign.Storable
import Raaz.Core


-- | The type associated with the ChaCha20 cipher.
data ChaCha20 = ChaCha20

-- | The type associated with the XChaCha20 variant.
data XChaCha20 = XChaCha20

type WORD     = LE Word32
type KEY      = Tuple 8 WORD

instance Primitive ChaCha20 where
  type WordType      ChaCha20 = WORD
  type WordsPerBlock ChaCha20 = 16

instance Primitive XChaCha20 where
  type WordType      XChaCha20  = WORD
  type WordsPerBlock XChaCha20  = 16


newtype instance Key     ChaCha20 = Key KEY
  deriving (Storable, EndianStore, Equality, Eq)

newtype instance Nounce  ChaCha20 = Nounce  (Tuple 3 WORD)
  deriving (Storable, EndianStore, Equality, Eq)

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


newtype instance Key     XChaCha20 = XKey KEY
  deriving (Storable, EndianStore)
newtype instance Nounce  XChaCha20 = XNounce  (Tuple 6 WORD)
  deriving (Storable, EndianStore)

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
                               , counterCell  :: MemoryCell WORD
                               }

keyCellPtr :: ChaCha20Mem -> Ptr (Key ChaCha20)
keyCellPtr = getCellPointer . keyCell

ivCellPtr :: ChaCha20Mem -> Ptr (Nounce ChaCha20)
ivCellPtr = getCellPointer . ivCell

counterCellPtr :: ChaCha20Mem -> Ptr WORD
counterCellPtr = getCellPointer . counterCell

instance Initialisable  (MemoryCell (Key ChaCha20)) (Key XChaCha20) where
  initialise = initialise . coerce
    where coerce (XKey k) = Key k

instance Memory ChaCha20Mem where
  memoryAlloc     = ChaCha20Mem <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . keyCell

instance Initialisable ChaCha20Mem (Key ChaCha20) where
  initialise key = initialise key . keyCell

instance Initialisable ChaCha20Mem (Nounce ChaCha20)  where
  initialise nounce = initialise nounce . ivCell

instance Initialisable ChaCha20Mem (BlockCount ChaCha20) where
  initialise bcount = initialise (conv bcount) . counterCell
    where conv :: BlockCount ChaCha20 -> WORD
          conv = toEnum . fromEnum

instance Extractable ChaCha20Mem (BlockCount ChaCha20) where
  extract = fmap conv . extract  . counterCell
    where conv :: WORD -> BlockCount ChaCha20
          conv = toEnum . fromEnum

-- | Initialises key from a buffer. Use this instance if you want to
-- initialise (only the) key from a secure memory location.
instance Accessible ChaCha20Mem where
  accessList = accessList . keyCell
