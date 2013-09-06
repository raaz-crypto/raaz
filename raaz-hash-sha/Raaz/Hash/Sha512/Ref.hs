{-|

This module gives the reference implementation of the sha512
hash. Depending on your platform there might be a more efficient
implementation. So you /should not/ be using this code in production.

-}

{-# LANGUAGE TemplateHaskell #-}

module Raaz.Hash.Sha512.Ref
       ( sha512CompressSingle
       ) where

import Control.Applicative

import Raaz.Types
import Raaz.Util.Ptr

import Raaz.Hash.Sha512.Type(SHA512(..))
import Raaz.Hash.Sha512.Ref.TH

-- | roundF function generated from TH
$(oneRound)
{-# INLINE roundF #-}

-- | Compresses one block.
sha512CompressSingle :: SHA512
                     -> CryptoPtr
                     -> IO SHA512
sha512CompressSingle sha512 cptr =
         roundF sha512
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
