{-|

A cryptographic cipher abstraction.

-}

{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE CPP                   #-}

module Raaz.Primitives.Cipher
       ( StreamGadget
       , Cipher(..)

       -- * Block Cipher Modes
       --
       -- A block cipher can be run in many different modes. These
       -- types capture the different modes of operation.
#if UseKinds
       , Mode(..)
#else
       , ECB(..), CBC(..), CTR(..)
#endif
       -- * Cipher gadget
       --
       -- A cipher that is a gadget should support both encryption and
       -- decryption. These mutually inverse operation are
       -- differentianted via a type argument.
#if UseKinds
       , Direction(..)
#else
       , Encryption(..), Decryption(..)
#endif
       ) where

import           Raaz.Primitives

#if UseKinds
data Mode = ECB -- ^ Electronic codebook
          | CBC -- ^ Cipher-block chaining
          | CTR -- ^ Counter
            deriving (Show, Eq)

-- | Direction of operation of cipher
data Direction = Encryption
               | Decryption
               deriving (Show, Eq)

-- | Type to capture Cipher Primitive
data Cipher cipher key (stage :: Direction) = Cipher deriving (Eq,Show)
#else

-- | Electronic codebook
data ECB = ECB deriving (Show, Eq)

-- | Cipher-block chaining
data CBC = CBC deriving (Show, Eq)

-- | Counter
data CTR = CTR deriving (Show,Eq)

-- | Encryption
data Encryption = Encryption deriving (Show, Eq)

-- | Decryption
data Decryption = Decryption deriving (Show, Eq)

-- | Type to capture Cipher Primitive
data Cipher cipher key stage = Cipher deriving (Eq,Show)
#endif

-- | This class captures gadgets which can be used as stream ciphers.
-- Any block cipher can also be seen as a stream cipher if it is run
-- in say counter mode.
class Gadget g => StreamGadget g
