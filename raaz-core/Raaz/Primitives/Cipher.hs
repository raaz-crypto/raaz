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

       -- * Block Cipher CipherModes
       --
       -- A block cipher can be run in many different modes. These
       -- types capture the different modes of operation.
#if UseKinds
       , CipherMode(..)
#else
       , ECB(..), CBC(..), CTR(..)
#endif
       , module Raaz.Primitives.Mode
       ) where

import Raaz.Primitives
import Raaz.Primitives.Mode

#if UseKinds
data CipherMode = ECB -- ^ Electronic codebook
          | CBC -- ^ Cipher-block chaining
          | CTR -- ^ Counter
            deriving (Show, Eq)

-- | Type to capture Cipher Primitive
data Cipher cipher key (direction :: Mode) = Cipher deriving (Eq,Show)
#else

-- | Electronic codebook
data ECB = ECB deriving (Show, Eq)

-- | Cipher-block chaining
data CBC = CBC deriving (Show, Eq)

-- | Counter
data CTR = CTR deriving (Show,Eq)

{-# DEPRECATED ECB, CBC, CTR
  "Will be changed to Data Constructor of type CipherMode from ghc7.6 onwards" #-}

-- | Type to capture Cipher Primitive
data Cipher cipher key direction = Cipher deriving (Eq,Show)

{-# DEPRECATED Cipher
  "Kind restrictions will be used in direction from ghc7.6 onwards" #-}
#endif

-- | This class captures gadgets which can be used as stream ciphers.
-- Any block cipher can also be seen as a stream cipher if it is run
-- in say counter mode.
class Gadget g => StreamGadget g
