{-|

A cryptographic cipher abstraction.

-}

{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE KindSignatures        #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE CPP                   #-}

module Raaz.Primitives.Cipher
       ( StreamGadget

       -- * Block Cipher CipherModes
       --
       -- A block cipher can be run in many different modes. These
       -- types capture the different modes of operation.
#if UseKinds
       , CipherMode(..)
#else
       , ECB(..), CBC(..), CTR(..)
#endif
       , module Raaz.Primitives.Symmetric
       ) where

import Raaz.Primitives
import Raaz.Primitives.Symmetric

#if UseKinds
data CipherMode = ECB -- ^ Electronic codebook
                | CBC -- ^ Cipher-block chaining
                | CTR -- ^ Counter
                deriving (Show, Eq)
#else

-- | Electronic codebook
data ECB = ECB deriving (Show, Eq)

-- | Cipher-block chaining
data CBC = CBC deriving (Show, Eq)

-- | Counter
data CTR = CTR deriving (Show,Eq)

{-# DEPRECATED ECB, CBC, CTR
  "Will be changed to Data Constructor of type CipherMode from ghc7.6 onwards" #-}
#endif

-- | This class captures gadgets which can be used as stream ciphers.
-- Any block cipher can also be seen as a stream cipher if it is run
-- in say counter mode.
class Gadget g => StreamGadget g
