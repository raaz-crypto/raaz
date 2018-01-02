{-# LANGUAGE DataKinds                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving       #-}
{-# LANGUAGE FlexibleInstances                #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE TypeFamilies                     #-}

-- | The internals of ChaCha20 ciphers.
module Raaz.Cipher.ChaCha20.Internal
       ( ChaCha20(..), WORD, Counter(..), IV(..), KEY(..), ChaCha20Mem(..)
       ) where

import Control.Applicative
import Data.Word
import Data.String
import Foreign.Storable
import Prelude


import Raaz.Core
import Raaz.Cipher.Internal

-- | The chacha20 stream cipher.


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
newtype Counter  = Counter (LE Word32) deriving (Num, Storable, EndianStore, Show, Eq, Ord)


-- | The key type.
newtype KEY      = ChaCha20Key (Tuple 8 WORD) deriving (Storable, EndianStore)

instance Encodable KEY

instance Show KEY where
  show = showBase16

instance IsString KEY where
  fromString = fromBase16

-- | The type associated with the ChaCha20 cipher.
data ChaCha20 = ChaCha20

instance Primitive ChaCha20 where
  type BlockSize ChaCha20      = 64
  type Implementation ChaCha20 = SomeCipherI ChaCha20
  type Key ChaCha20 = (KEY, IV, Counter)

instance Describable ChaCha20 where
  name        _ = "chacha20"
  description _ = "The ChaCha20 cipher"

instance Cipher ChaCha20

instance StreamCipher ChaCha20



---------- Memory for ChaCha20 implementations  ------------------
-- | chacha20 memory
data ChaCha20Mem = ChaCha20Mem { keyCell      :: MemoryCell KEY
                               , ivCell       :: MemoryCell IV
                               , counterCell  :: MemoryCell Counter
                               }


instance Memory ChaCha20Mem where
  memoryAlloc     = ChaCha20Mem <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . keyCell

instance Initialisable ChaCha20Mem (KEY, IV, Counter) where
  initialise (k,iv,ctr) = do onSubMemory keyCell     $ initialise k
                             onSubMemory ivCell      $ initialise iv
                             onSubMemory counterCell $ initialise ctr


instance Initialisable ChaCha20Mem (KEY, IV) where
  initialise (k, iv) = initialise (k, iv, 0 :: Counter)
