-- Generic tests for hash.

module Generic.Hash where

import Data.ByteString hiding (replicate)
import Data.Monoid
import Test.Hspec

import Generic.Utils
import Raaz.Core hiding ( replicate)
import Raaz.Hash

--
-- For unit tests for hash we have the following idiom
--
-- using sha1 [ hashing x1 shouldGive y1, hashing x2 shouldGive y2]
-- where y1 is the hexadecimal encoding of the hash of x2.
--

hashesTo :: (Hash h, Encodable h, Show h)
         => ByteString
         -> h
         -> Spec
hashesTo str h = it msg (hash str `shouldBe` h)
  where msg   = unwords [ "hashes"
                        , shortened $ show str
                        , "to"
                        , shortened $ show h
                        ]

hmacsTo :: ( Hash h, Show h)
        => ByteString
        -> HMAC h
        -> Key (HMAC h)
        -> Spec
hmacsTo str hm key = it mesg $ hmac key str `shouldBe` hm
  where mesg       = unwords [ "with key", shortened $ show key
                             ,  shortened $ show str
                             ,  "hmacs to"
                             ,  shortened $ show hm
                             ]


repeated :: Monoid m => m -> Int -> m
repeated m n = mconcat $ replicate n m
