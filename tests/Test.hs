-- | This module collects all generic tests

module Test
       ( module Test.Cipher
       , module Test.EndianStore
       , module Test.Gadget
       ) where

import Test.Cipher
import Test.EndianStore
import Test.Gadget

{-# ANN module "HLint: ignore Use import/export shortcut" #-}
