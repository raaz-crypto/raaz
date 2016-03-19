-- Generic tests for hash.

module Common.Hash
       ( hashesTo
       , hmacsTo
       ) where

import Common.Imports  hiding (replicate)
import Common.Utils

--
-- For unit tests for hash we have the following idiom
--
-- using sha1 [ hashing x1 shouldGive y1, hashing x2 shouldGive y2]
-- where y1 is the hexadecimal encoding of the hash of x2.
--

hashesTo :: (Hash h, Recommendation h, Encodable h, Show h)
         => ByteString
         -> h
         -> Spec
hashesTo str h = it msg (hash str `shouldBe` h)
  where msg   = unwords [ "hashes"
                        , shortened $ show str
                        , "to"
                        , shortened $ show h
                        ]

hmacsTo :: ( Hash h, Recommendation h, Show h)
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
