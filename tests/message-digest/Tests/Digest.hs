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
incrDigest bs = withMemory $ \ (cxt :: DigestCxt 1) ->
  do startDigest cxt
     updateDigest bs cxt
     finaliseDigest cxt

incrDigestList :: [ByteString]
               -> IO Prim
incrDigestList bsL = withMemory $ \ (cxt :: DigestCxt 1) ->
  do startDigest cxt
     mapM_ (`updateDigest` cxt) bsL
     finaliseDigest cxt

incrementalVsFull :: Spec
incrementalVsFull = describe "Incremental vs Full digest" $ do
  prop "for single source" $
    \ bs -> incrDigest bs `shouldReturn` digest bs

  prop "for multiple source" $
    \ bsL -> incrDigestList bsL `shouldReturn` digest bsL
