{-

A cryptographic cipher abstraction.

-}

{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE EmptyDataDecls        #-}
{-# LANGUAGE DeriveDataTypeable    #-}

module Raaz.Primitives.Cipher
       ( CipherGadget
       , StreamGadget
       -- * Block Cipher Modes
       , ECB, CBC, CTR
       -- * Stages
       , Encryption, Decryption
       ) where

import           Data.Typeable

import           Raaz.Primitives

-- | Electronic codebook
data ECB deriving (Typeable)

-- | Cipher-block chaining
data CBC deriving (Typeable)

-- | Counter
data CTR deriving (Typeable)

-- | Encryption
data Encryption deriving (Typeable)

-- | Decryption
data Decryption deriving (Typeable)

-- | This class captures encryption and decryption by a Cipher. User
-- need to take care of padding externally and ensure that bytestring
-- is in multiple of blocksize of the underlying cipher.
class ( Gadget (g Encryption)
      , Gadget (g Decryption)
      , Initializable (PrimitiveOf (g Encryption))
      , Initializable (PrimitiveOf (g Decryption))
      ) => CipherGadget g


-- | This class captures gadgets which can be used as stream ciphers.
class Gadget g => StreamGadget g
