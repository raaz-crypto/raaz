{-# LANGUAGE FlexibleContexts #-}
-- Generic tests for hash.

module Tests.Digest
       ( digestsTo
       ) where

import Implementation
import Interface

import Tests.Core



digestsTo :: (Show Prim, Eq Prim)
          => ByteString
          -> Prim
          -> Spec
digestsTo str h = it msg (digest str `shouldBe` h)
  where msg   = unwords [ "hashes"
                        , shortened $ show str
                        , "to"
                        , shortened $ show h
                        ]
