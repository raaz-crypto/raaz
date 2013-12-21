{-

A cryptographic cipher abstraction.

-}

{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE EmptyDataDecls        #-}
{-# LANGUAGE DeriveDataTypeable    #-}

module Raaz.Primitives.Cipher
       ( CipherGadget
       , ECB, CBC, CTR
       , Encryption, Decryption
       , StreamGadget
       ) where

import           Data.Typeable

import           Raaz.Primitives

-- | Block Ciphers can work in a number of modes which is captured by
-- this datatype
data ECB deriving (Typeable)   -- ^ Electronic codebook
data CBC deriving (Typeable)   -- ^ Cipher-block chaining
data CTR deriving (Typeable)   -- ^ Counter

-- | Ciphers work in two stages
-- * Encryption
-- * Decryption
data Encryption deriving (Typeable)
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
