{-|

A cryptographic cipher abstraction.

-}

{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE EmptyDataDecls        #-}
{-# LANGUAGE DeriveDataTypeable    #-}

module Raaz.Primitives.Cipher
       ( CipherGadget
       , StreamGadget

       -- * Block Cipher Modes
       --
       -- A block cipher can be run in many different modes. These
       -- types capture the different modes of operation.
       , ECB, CBC, CTR

       -- * Cipher gadget
       --
       -- A cipher that is a gadget should support both encryption and
       -- decryption. These mutually inverse operation are
       -- differentianted via a type argument.
       , Encryption, Decryption
       ) where

import           Data.Typeable

import           Raaz.Primitives

-- | Electronic codebook
data ECB deriving Typeable

-- | Cipher-block chaining
data CBC deriving Typeable

-- | Counter
data CTR deriving Typeable

-- | Encryption
data Encryption deriving Typeable

-- | Decryption
data Decryption deriving Typeable

-- | A cipher gadget is one that supports both encryption and
-- decryption. For block ciphers, we do not take care of padding. In
-- fact there are no standard ways to pad messages and these are
-- usually application dependent.
class ( Gadget (g Encryption)
      , Gadget (g Decryption)
      , Initializable (PrimitiveOf (g Encryption))
      , Initializable (PrimitiveOf (g Decryption))
      ) => CipherGadget g


-- | This class captures gadgets which can be used as stream ciphers.
-- Any block cipher can also be seen as a stream cipher if it is run
-- in say counter mode.
class Gadget g => StreamGadget g
