{-# LANGUAGE DataKinds                        #-}
{-# LANGUAGE KindSignatures                   #-}
{-# LANGUAGE GeneralizedNewtypeDeriving       #-}
{-# LANGUAGE ForeignFunctionInterface         #-}
{-# LANGUAGE FlexibleInstances                #-}
{-# LANGUAGE MultiParamTypeClasses            #-}
{-# LANGUAGE EmptyDataDecls                   #-}
{-# CFILES raaz/cipher/aes/common/expand.c    #-}

module Raaz.Cipher.AES.Type
       ( AES(..), RowMem(..), AESWord, AESTuple, KEY128,
       ) where

import Data.Word
import Data.String
import Foreign.Ptr      (castPtr )
import Foreign.Storable (Storable, poke)
import GHC.TypeLits


import Raaz.Core
import Raaz.Cipher.Internal

-- | The AES type.
data AES (n :: Nat) (mode :: CipherMode) = AES

-- | The basic word used in AES.
type AESWord    = BE Word32

-- | A tuple of AES words.
type AESTuple n = Tuple n AESWord

-- | Key used for AES-128
newtype KEY128 = KEY128 (AESTuple 4) deriving (Storable, EndianStore)

instance Encodable KEY128

instance IsString KEY128 where
  fromString = fromBase16

instance Show KEY128 where
  show = showBase16


-- | Memory used to store AESWords as rows.
newtype RowMem (n :: Nat) = RowMem { unRowMem :: MemoryCell (AESTuple n) }
                          deriving Memory

instance Initialisable (RowMem 44) KEY128 where
  initialise k = liftSubMT unRowMem $ withCell $ pokeExpandAndTranspose k c_expand128 11

foreign import ccall unsafe
  "raaz/cipher/aes/common/common.h raazAESExpand128"
  c_expand128 :: Pointer -> IO ()

foreign import ccall unsafe
  "raaz/cipher/aes/common/common.h raazAESTranspose"
  c_transpose :: Int -> Pointer -> IO ()

-- | Poke a key and expand it with the given routine.
pokeAndExpand :: Storable k
              => k                   -- ^ key to poke
              -> (Pointer -> IO ())  -- ^ expansion algorithm
              -> Pointer             -- ^ buffer pointer.
              -> IO ()
pokeAndExpand k expander ptr = poke (castPtr ptr) k >> expander ptr

-- | Poke the key, expand and transpose
pokeExpandAndTranspose :: Storable k
                       => k                  -- ^ the key to poke
                       -> (Pointer -> IO())  -- ^ the expansion algorithm
                       -> Int                -- ^ number of matrix element to transpose
                       -> Pointer            -- buffer pointer
                       -> IO ()
pokeExpandAndTranspose k expander n ptr = pokeAndExpand k expander ptr
                                        >> c_transpose n ptr
