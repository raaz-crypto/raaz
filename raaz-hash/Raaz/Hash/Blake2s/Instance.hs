{-|

This module defines the hash instances for blake2b hash.

-}

{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Hash.Blake2s.Instance () where

import Control.Monad       ( foldM )
import Data.Default()
import Data.Word

import Raaz.Core.Memory
import Raaz.Core.Primitives
import Raaz.Core.Primitives.Hash
import Raaz.Core.Types
import Raaz.Core.Util.Ptr

import Raaz.Hash.Blake2s.Type
--import Raaz.Hash.Blake256.Ref
import Raaz.Hash.Blake2s.CPortable


----------------------------- BLAKE2b -------------------------------------------

instance CryptoPrimitive BLAKE2S where
  type Recommended BLAKE2S = CGadget BLAKE2S
  type Reference BLAKE2S   = CGadget BLAKE2S

instance Hash BLAKE2S