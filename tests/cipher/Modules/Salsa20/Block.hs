{-# LANGUAGE OverloadedStrings #-}
module Modules.Salsa20.Block
       ( tests
       ) where

import           Control.Applicative
import           Data.ByteString                      ( ByteString        )
import qualified Data.ByteString                      as BS
import           Test.Framework                       ( Test,testGroup    )
import           Test.Framework.Providers.QuickCheck2 ( testProperty      )
import           Test.QuickCheck                      ( Arbitrary(..)     )
import           Test.HUnit                           ( (~?=), test, (~:) )
import           Test.Framework.Providers.HUnit       ( hUnitTestToTests  )


import           Test.Cipher                ( shorten           )
import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString

import           Raaz.Cipher.Salsa20.Internal

instance Arbitrary STATE where
  arbitrary = STATE <$> arbitrary
                    <*> arbitrary
                    <*> arbitrary
                    <*> arbitrary

quarterRoundVec :: [(STATE,STATE)]
quarterRoundVec = [ ( STATE 0x00000000 0x00000000 0x00000000 0x00000000
                    , STATE 0x00000000 0x00000000 0x00000000 0x00000000 )
                  , ( STATE 0x00000001 0x00000000 0x00000000 0x00000000
                    , STATE 0x08008145 0x00000080 0x00010200 0x20500000 )
                  , ( STATE 0x00000000 0x00000001 0x00000000 0x00000000
                    , STATE 0x88000100 0x00000001 0x00000200 0x00402000 )
                  , ( STATE 0x00000000 0x00000000 0x00000001 0x00000000
                    , STATE 0x80040000 0x00000000 0x00000001 0x00002000 )
                  , ( STATE 0x00000000 0x00000000 0x00000000 0x00000001
                    , STATE 0x00048044 0x00000080 0x00010000 0x20100001 )
                  , ( STATE 0xe7e8c006 0xc4f9417d 0x6479b4b2 0x68c67137
                    , STATE 0xe876d72b 0x9361dfd5 0xf1460244 0x948541a3 )
                  , ( STATE 0xd3917c5b 0x55f1c407 0x52a58a7a 0x8f887a3b
                    , STATE 0x3e2f308c 0xd90a8f36 0x6ab2a923 0x2883524c )
                  ]

rowRoundVec :: [(Matrix,Matrix)]
rowRoundVec = [ ( Matrix
                   (STATE 0x00000001 0x00000000 0x00000000 0x00000000)
                   (STATE 0x00000001 0x00000000 0x00000000 0x00000000)
                   (STATE 0x00000001 0x00000000 0x00000000 0x00000000)
                   (STATE 0x00000001 0x00000000 0x00000000 0x00000000)
                , Matrix
                   (STATE 0x08008145 0x00000080 0x00010200 0x20500000)
                   (STATE 0x20100001 0x00048044 0x00000080 0x00010000)
                   (STATE 0x00000001 0x00002000 0x80040000 0x00000000)
                   (STATE 0x00000001 0x00000200 0x00402000 0x88000100) )
              , ( Matrix
                   (STATE 0x08521bd6 0x1fe88837 0xbb2aa576 0x3aa26365)
                   (STATE 0xc54c6a5b 0x2fc74c2f 0x6dd39cc3 0xda0a64f6)
                   (STATE 0x90a2f23d 0x067f95a6 0x06b35f61 0x41e4732e)
                   (STATE 0xe859c100 0xea4d84b7 0x0f619bff 0xbc6e965a)
                , Matrix
                   (STATE 0xa890d39d 0x65d71596 0xe9487daa 0xc8ca6a86)
                   (STATE 0x949d2192 0x764b7754 0xe408d9b9 0x7a41b4d1)
                   (STATE 0x3402e183 0x3c3af432 0x50669f96 0xd89ef0a8)
                   (STATE 0x0040ede5 0xb545fbce 0xd257ed4f 0x1818882d) )
              ]

colRoundVec :: [(Matrix,Matrix)]
colRoundVec = [ ( Matrix
                   (STATE 0x00000001 0x00000000 0x00000000 0x00000000)
                   (STATE 0x00000001 0x00000000 0x00000000 0x00000000)
                   (STATE 0x00000001 0x00000000 0x00000000 0x00000000)
                   (STATE 0x00000001 0x00000000 0x00000000 0x00000000)
                , Matrix
                   (STATE 0x10090288 0x00000000 0x00000000 0x00000000)
                   (STATE 0x00000101 0x00000000 0x00000000 0x00000000)
                   (STATE 0x00020401 0x00000000 0x00000000 0x00000000)
                   (STATE 0x40a04001 0x00000000 0x00000000 0x00000000) )
              , ( Matrix
                   (STATE 0x08521bd6 0x1fe88837 0xbb2aa576 0x3aa26365)
                   (STATE 0xc54c6a5b 0x2fc74c2f 0x6dd39cc3 0xda0a64f6)
                   (STATE 0x90a2f23d 0x067f95a6 0x06b35f61 0x41e4732e)
                   (STATE 0xe859c100 0xea4d84b7 0x0f619bff 0xbc6e965a)
                , Matrix
                   (STATE 0x8c9d190a 0xce8e4c90 0x1ef8e9d3 0x1326a71a)
                   (STATE 0x90a20123 0xead3c4f3 0x63a091a0 0xf0708d69)
                   (STATE 0x789b010c 0xd195a681 0xeb7d5504 0xa774135c)
                   (STATE 0x481c2027 0x53a8e4b5 0x4c1f89c5 0x3f78c9c8) )
              ]

doubleRoundVec :: [(Matrix,Matrix)]
doubleRoundVec = [ ( Matrix
                      (STATE 0x00000001 0x00000000 0x00000000 0x00000000)
                      (STATE 0x00000000 0x00000000 0x00000000 0x00000000)
                      (STATE 0x00000000 0x00000000 0x00000000 0x00000000)
                      (STATE 0x00000000 0x00000000 0x00000000 0x00000000)
                   , Matrix
                      (STATE 0x8186a22d 0x0040a284 0x82479210 0x06929051)
                      (STATE 0x08000090 0x02402200 0x00004000 0x00800000)
                      (STATE 0x00010200 0x20400000 0x08008104 0x00000000)
                      (STATE 0x20500000 0xa0000040 0x0008180a 0x612a8020) )
                 , ( Matrix
                      (STATE 0xde501066 0x6f9eb8f7 0xe4fbbd9b 0x454e3f57)
                      (STATE 0xb75540d3 0x43e93a4c 0x3a6f2aa0 0x726d6b36)
                      (STATE 0x9243f484 0x9145d1e8 0x4fa9d247 0xdc8dee11)
                      (STATE 0x054bf545 0x254dd653 0xd9421b6d 0x67b276c1)
                   , Matrix
                      (STATE 0xccaaf672 0x23d960f7 0x9153e63a 0xcd9a60d0)
                      (STATE 0x50440492 0xf07cad19 0xae344aa0 0xdf4cfdfc)
                      (STATE 0xca531c29 0x8e7943db 0xac1680cd 0xd503ca00)
                      (STATE 0xa74b2ad6 0xbc331c5c 0x1dda24c7 0xee928277) )
                 ]

salsa20Vec :: [(ByteString,ByteString)]
salsa20Vec = [ ( BS.pack [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                         , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                         , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                         , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
               , BS.pack [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                         , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                         , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                         , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ] )
             , ( BS.pack [ 211,159, 13,115, 76, 55, 82,183, 3,117,222, 37,191,187,234,136
                         , 49,237,179, 48, 1,106,178,219,175,199,166, 48, 86, 16,179,207
                         , 31,240, 32, 63, 15, 83, 93,161,116,147, 48,113,238, 55,204, 36
                         , 79,201,235, 79, 3, 81,156, 47,203, 26,244,243, 88,118,104, 54  ]
               , BS.pack [ 109, 42,178,168,156,240,248,238,168,196,190,203, 26,110,170,154
                         ,29, 29,150, 26,150, 30,235,249,190,163,251, 48, 69,144, 51, 57
                         ,118, 40,152,157,180, 57, 27, 94,107, 42,236, 35, 27,111,114,114
                         ,219,236,232,135,111,155,110, 18, 24,232, 95,158,179, 19, 48,202 ] )
             , ( BS.pack [ 88,118,104, 54, 79,201,235, 79, 3, 81,156, 47,203, 26,244,243
                         , 191,187,234,136,211,159, 13,115, 76, 55, 82,183, 3,117,222, 37
                         , 86, 16,179,207, 49,237,179, 48, 1,106,178,219,175,199,166, 48
                         , 238, 55,204, 36, 31,240, 32, 63, 15, 83, 93,161,116,147, 48,113 ]
               , BS.pack [179, 19, 48,202,219,236,232,135,111,155,110, 18, 24,232, 95,158
                         ,26,110,170,154,109, 42,178,168,156,240,248,238,168,196,190,203
                         ,69,144, 51, 57, 29, 29,150, 26,150, 30,235,249,190,163,251, 48
                         ,27,111,114,114,118, 40,152,157,180, 57, 27, 94,107, 42,236, 35] )
             ]

salsa20Key128Vec :: [(KEY128,Nonce,Counter,Matrix)]
salsa20Key128Vec = [ ( fromByteString $ BS.pack [1..16]
                     , fromByteString $ BS.pack [101..108]
                     , fromByteString $ BS.pack [109..116]
                     , fromByteString $ BS.pack [ 39,173, 46,248, 30,200, 82, 17, 48, 67,254,239, 37, 18, 13,247
                                                , 241,200, 61,144, 10, 55, 50,185, 6, 47,246,253,143, 86,187,225
                                                , 134, 85,110,246,161,163, 43,235,231, 94,171, 51,145,214,112, 29
                                                , 14,232, 5, 16,151,140,183,141,171, 9,122,181,104,182,177,193 ]
                     )
                   ]

salsa20Key256Vec :: [(KEY256,Nonce,Counter,Matrix)]
salsa20Key256Vec = [ ( fromByteString $ BS.pack ([1..16] ++ [201..216])
                     , fromByteString $ BS.pack [101..108]
                     , fromByteString $ BS.pack [109..116]
                     , fromByteString $ BS.pack [ 69, 37, 68, 39, 41, 15,107,193,255,139,122, 6,170,233,217, 98
                                                , 89,144,182,106, 21, 51,200, 65,239, 49,222, 34,215,114, 40,126
                                                , 104,197, 7,225,197,153, 31, 2,102, 78, 76,176, 84,245,246,184
                                                , 177,160,133,130, 6, 72,149,119,192,195,132,236,234,103,246, 74 ]
                     )
                   ]

testQuarterRound :: [(STATE,STATE)] -> Test
testQuarterRound = testGroup "QuarterRound unit tests" . hUnitTestToTests . test . map check
  where check (a,b) = shorten (show a) ~: quarterRound a ~?= b

testRowRound :: [(Matrix,Matrix)] -> Test
testRowRound = testGroup "RowRound unit tests" . hUnitTestToTests . test . map check
  where check (a,b) = shorten (show a) ~: rowRound a ~?= b

testColRound :: [(Matrix,Matrix)] -> Test
testColRound = testGroup "ColRound unit tests" . hUnitTestToTests . test . map check
  where check (a,b) = shorten (show a) ~: colRound a ~?= b

testDoubleRound :: [(Matrix,Matrix)] -> Test
testDoubleRound = testGroup "DoubleRound unit tests" . hUnitTestToTests . test . map check
  where check (a,b) = shorten (show a) ~: doubleRound a ~?= b

testSalsa20 :: [(ByteString,ByteString)] -> Test
testSalsa20 = testGroup "Salsa20 unit tests" . hUnitTestToTests . test . map check
  where check (a,b) = shorten (show a) ~: toByteString (salsa20 20 $ fromByteString a) ~?= b

testSalsa20Key128 :: [(KEY128,Nonce,Counter,Matrix)] -> Test
testSalsa20Key128 = testGroup "Salsa20 unit tests" . hUnitTestToTests . test . map check
  where check (k,n,c,e) = shorten (show k) ~: salsa20 20 (expand128 k n c) ~?= e

testSalsa20Key256 :: [(KEY256,Nonce,Counter,Matrix)] -> Test
testSalsa20Key256 = testGroup "Salsa20 unit tests" . hUnitTestToTests . test . map check
  where check (k,n,c,e) = shorten (show k) ~: salsa20 20 (expand256 k n c) ~?= e

tests :: [Test]
tests = [ testQuarterRound quarterRoundVec
        , testRowRound rowRoundVec
        , testColRound colRoundVec
        , testDoubleRound doubleRoundVec
        , testSalsa20 salsa20Vec
        , testSalsa20Key128 salsa20Key128Vec
        , testSalsa20Key256 salsa20Key256Vec
        ]
