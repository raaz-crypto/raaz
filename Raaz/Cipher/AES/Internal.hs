{-# LANGUAGE DataKinds                        #-}
{-# LANGUAGE KindSignatures                   #-}
{-# LANGUAGE GeneralizedNewtypeDeriving       #-}
{-# LANGUAGE ForeignFunctionInterface         #-}
{-# LANGUAGE FlexibleInstances                #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE TypeFamilies                     #-}

module Raaz.Cipher.AES.Internal
       ( AES(..), WORD, TUPLE, KEY128, IV
       , aes128cbc, aes128ctr
       ) where

import Data.String
import Data.Word

import Foreign.Ptr      (castPtr )
import Foreign.Storable (Storable, poke)
import GHC.TypeLits


import Raaz.Core
import Raaz.Cipher.Internal

--------------- Basic types associated with AES -------------

-- | The AES cipher.
data AES (n :: Nat) (mode :: CipherMode) = AES

-- | The basic word used in AES.
type WORD    = BE Word32

-- | A tuple of AES words.
type TUPLE n = Tuple n WORD


-- | Key used for AES-128
newtype KEY128  = KEY128  (TUPLE 4)  deriving (Storable, EndianStore)

instance Encodable KEY128

instance IsString KEY128 where
  fromString = fromBase16

instance Show KEY128 where
  show = showBase16

--------------- AES CBC ---------------------------------

-- | Smart constructors for AES 128 cbc.
aes128cbc :: AES 128 CBC
aes128cbc = AES

-- | The IV used by the CBC mode.
newtype IV      = IV (TUPLE 4) deriving (Storable, EndianStore)

instance Encodable IV

-- | Read as a base16 string.
instance IsString IV where
  fromString = fromBase16

-- | Shown as a its base16 encoding.
instance Show IV where
  show = showBase16

-- | The 128-bit aes cipher in cbc mode.
instance Primitive (AES 128 CBC) where
  blockSize _ = BYTES 16
  type Implementation (AES 128 CBC) = SomeCipherI (AES 128 CBC)

-- | Key is @(`KEY128`,`IV`)@ pair.
instance Symmetric (AES 128 CBC) where
  type Key (AES 128 CBC) = (KEY128,IV)

------------------- AES CTR mode ---------------------------

-- | Smart constructors for AES 128 ctr.
aes128ctr :: AES 128 CTR
aes128ctr = AES

--------------  Memory for storing extended keys ---------

newtype EKEY128 = EKEY128 (TUPLE 44) deriving Storable

instance Initialisable (MemoryCell EKEY128) KEY128 where
  initialise k = withPointer $ pokeAndExpand k c_expand128

foreign import ccall unsafe
  "raaz/cipher/aes/common.h raazAESExpand128"
  c_expand128 :: Pointer -> IO ()

-- | Poke a key and expand it with the given routine.
pokeAndExpand :: Storable k
              => k                   -- ^ key to poke
              -> (Pointer -> IO ())  -- ^ expansion algorithm
              -> Pointer             -- ^ buffer pointer.
              -> IO ()
pokeAndExpand k expander ptr = poke (castPtr ptr) k >> expander ptr
