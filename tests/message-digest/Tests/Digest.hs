{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE MonoLocalBinds      #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- Generic tests for hash.

module Tests.Digest
       ( digestsTo
       , incrementalVsFull
       ) where

import Implementation
import Interface

import Tests.Core



digestsTo :: ByteString
          -> Prim
          -> Spec
digestsTo str h = it msg (digest str `shouldBe` h)
  where msg   = unwords [ "hashes"
                        , shortened $ show str
                        , "to"
                        , shortened $ show h
                        ]

incrDigest :: ByteString
           -> IO Prim
incrDigest bs = withMemory $ \ (cxt :: Cxt 16) ->
  do start cxt
     update bs cxt
     finalise cxt

incrementalVsFull :: Spec
incrementalVsFull = prop "incremental vs full" $
  \ bs -> incrDigest bs `shouldReturn` digest bs
