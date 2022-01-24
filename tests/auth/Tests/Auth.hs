-- Generic tests for hash.
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE MonoLocalBinds   #-}
{-# LANGUAGE DataKinds           #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Tests.Auth
       ( authsTo
       , incrementalVsFull
       , auth
       ) where

import Implementation
import Interface
import Tests.Core

authsTo :: ByteString
        -> Prim
        -> Key Prim
        -> Spec
authsTo str prim key = it msg (auth key str `shouldBe` prim)
  where msg   = unwords [ "authenticates"
                        , shortened $ show str
                        , "to"
                        , shortened $ show prim
                        ]


incrDigest :: Key Prim
           -> ByteString
           -> IO Prim
incrDigest k bs = withMemory $ \ (cxt :: AuthCxt 1) ->
  do startAuth k cxt
     updateAuth bs cxt
     finaliseAuth cxt

incrDigestList :: Key Prim
               -> [ByteString]
               -> IO Prim
incrDigestList k bsL = withMemory $ \ (cxt :: AuthCxt 1) ->
  do startAuth k cxt
     mapM_ (`updateAuth` cxt) bsL
     finaliseAuth cxt

incrementalVsFull :: Spec
incrementalVsFull = describe "Incremental vs Full authenticator" $ do
  prop "for single source" $
    \ k bs -> incrDigest k bs `shouldReturn` auth k bs

  prop "for multiple source" $
    \ k bsL -> incrDigestList k bsL `shouldReturn` auth k bsL
