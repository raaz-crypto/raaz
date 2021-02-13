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
incrDigest bs = withMemory $ \ (cxt :: Cxt 1) ->
  do start cxt
     update bs cxt
     finalise cxt

incrDigestList :: [ByteString]
               -> IO Prim
incrDigestList bsL = withMemory $ \ (cxt :: Cxt 1) ->
  do start cxt
     mapM_ (flip update cxt) bsL
     finalise cxt

incrementalVsFull :: Spec
incrementalVsFull = describe "Incremental vs Full digest" $ do
  prop "for single source" $
    \ bs -> incrDigest bs `shouldReturn` digest bs

  prop "for multiple source" $
    \ bsL -> incrDigestList bsL `shouldReturn` digest bsL
