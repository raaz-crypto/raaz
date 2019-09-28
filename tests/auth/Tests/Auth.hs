-- Generic tests for hash.
{-# LANGUAGE FlexibleContexts #-}
module Tests.Auth
       ( authsTo
       ) where


import Data.ByteString (ByteString)
import Implementation
import Interface
import Tests.Core



authsTo :: (Show Prim, Show (Key Prim), Eq Prim)
        => ByteString
        -> Prim
        -> Key Prim
        -> Spec
authsTo str prim key = it msg (auth key str `shouldBe` prim)
  where msg   = unwords [ "authenticates"
                        , shortened $ show str
                        , "to"
                        , shortened $ show prim
                        ]
