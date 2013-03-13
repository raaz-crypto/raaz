{-|

This module gives the reference implementation of the sha256
hash. Depending on your platform there might be a more efficient
implementation. So you /should not/ be using this code in production.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha256.Ref.Sha256
       ( sha256CompressSingle
       ) where

import Control.Applicative

import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Hash.Sha256.Type(SHA256(..))
import Raaz.Hash.Sha256.Ref.Sha256TH

-- | roundF function generated from TH
$(oneRound)
{-# INLINE roundF #-}

-- | Compresses one block.
sha256CompressSingle :: SHA256
                   -> CryptoPtr
                   -> IO SHA256
sha256CompressSingle (SHA256 h0 h1 h2 h3 h4 h5 h6 h7) cptr =
         roundF h0 h1 h2 h3 h4 h5 h6 h7
         <$> load cptr
         <*> loadFromIndex cptr 1
         <*> loadFromIndex cptr 2
         <*> loadFromIndex cptr 3
         <*> loadFromIndex cptr 4
         <*> loadFromIndex cptr 5
         <*> loadFromIndex cptr 6
         <*> loadFromIndex cptr 7
         <*> loadFromIndex cptr 8
         <*> loadFromIndex cptr 9
         <*> loadFromIndex cptr 10
         <*> loadFromIndex cptr 11
         <*> loadFromIndex cptr 12
         <*> loadFromIndex cptr 13
         <*> loadFromIndex cptr 14
         <*> loadFromIndex cptr 15
