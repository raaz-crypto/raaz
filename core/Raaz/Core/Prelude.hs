{-# LANGUAGE CPP #-}
-- |
--
-- Module      : Raaz.Core.Prelude
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--

module Raaz.Core.Prelude ( module X
                         , module Prelude
                         ) where

import Control.Applicative          as X
import Control.Monad                as X
import Data.Bits                    as X
import Data.ByteString.Char8           ()
import Data.ByteString.Lazy.Char8      ()
import Data.Maybe                   as X
import Data.Proxy                   as X

import Data.String             as X
import Data.Word               as X
import Prelude hiding (length, replicate, zipWith)
import System.IO               as X
