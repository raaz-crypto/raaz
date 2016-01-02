{-|

A cryptographic cipher abstraction.

-}

{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE CPP                   #-}

module Raaz.Core.Primitives.Cipher
       ( StreamGadget

       -- * Block Cipher CipherModes
       --
       -- A block cipher can be run in many different modes. These
       -- types capture the different modes of operation.
       , CipherMode(..)
       , module Raaz.Core.Primitives.Symmetric
       ) where

import Raaz.Core.Primitives
import Raaz.Core.Primitives.Symmetric


data CipherMode = ECB -- ^ Electronic codebook
                | CBC -- ^ Cipher-block chaining
                | CTR -- ^ Counter
                deriving (Show, Eq)

-- | This class captures gadgets which can be used as stream ciphers.
-- Any block cipher can also be seen as a stream cipher if it is run
-- in say counter mode.
class Gadget g => StreamGadget g
