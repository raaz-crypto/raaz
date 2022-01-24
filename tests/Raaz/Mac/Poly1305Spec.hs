{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE DataKinds            #-}

module Raaz.Mac.Poly1305Spec where

import qualified Data.Vector.Unboxed as V
import           Data.Vector.Unboxed ( (!) )
import           Tests.Core
import           Poly1305.Auth
import           Raaz.Random
import qualified Data.ByteString as BS

import           Raaz.Primitive.Poly1305.Internal

randomClamping :: Spec
randomClamping = it "randomly generated R values should be clamped"
       $ checkClamped `shouldReturn` True
  where randR :: RandomState -> IO R
        randR = random
        checkClamped = withRandomState (fmap isClamped . randR)


-- | Check whether the given value of r is clamped.
isClamped :: R -> Bool
isClamped = isClampedStr . toByteString
  where top4Clear w = w < 16
        bot2Clear w = w `mod` 4  == 0
        isClampedStr bs = check top4Clear [3,7,11,15] && check bot2Clear [4,8,12]
          where check pr  = all (pr . BS.index bs)

spec :: Spec
spec = do
  describe "Poly1305" $
    basicEndianSpecs (undefined :: Poly1305)
  describe "R" $ do
    basicEndianSpecs (undefined :: R)
    randomClamping

  describe "S" $
    basicEndianSpecs (undefined :: S)

  incrementalVsFull

  with (Key "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8"
            "01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b"
       )
    $ ( "Cryptographic Forum Research Group" :: ByteString)
    `authsTo` ("a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9" :: Poly1305)

  describe "vs Integer based implementation" $ do
    prop "should be identical" $
      \ k str -> auth k str `shouldBe` poly1305 k str

-------------------------------------------------------------------------------
--    Poly1305 using the Integer Type
--
-- WARNING: only to be used for testing, it is slow and unsafe.
--

-- ^ The prime 2^130 - 5
prime :: Integer
prime = bit 130 - 5

fromWORD :: WORD -> Integer
fromWORD w128 = b0 + shiftL b1 64
  where vec = unsafeToVector w128
        b0  = fromIntegral (vec ! 0)
        b1  = fromIntegral (vec ! 1)

toWORD :: Integer -> WORD
toWORD i = unsafeFromVector $ V.fromList [b0 , b1]
  where b0 = fromIntegral i
        b1 = fromIntegral (shiftR i 64)

fromR :: R -> Integer
fromR (R r) = foldl clearBit v $
              [ 28, 29, 30, 31 ]    ++ [32, 33] ++
              [ 60, 61, 62, 63 ]    ++ [64, 65] ++
              [ 92, 93, 94, 95 ]    ++ [96, 97] ++
              [ 124, 125, 126, 127]
  where v = fromWORD r


fromS :: S -> Integer
fromS (S s) = fromWORD s

toPoly1305 :: Integer -> Poly1305
toPoly1305 = Poly1305 . toWORD

-- | Split the message byte string to integers
chunks :: ByteString -> [Integer]
chunks = map toI . chunkBS
  where chunkBS bs
          | BS.null bs  = []
          | otherwise           = let (start, rest) = BS.splitAt 16 bs
                                  in start : chunkBS rest

        addByte :: Word8 -> Integer -> Integer
        addByte w8 i = shiftL i 8 + fromIntegral w8
        toI = BS.foldr addByte 1

eval :: R -> [Integer] -> Integer
eval r = foldl fl 0
  where rI = fromR r
        fl acc msg = ((acc + msg) * rI)  `rem` prime


poly1305 :: Key Poly1305 -> ByteString -> Poly1305
poly1305 (Key r s) bs = toPoly1305 $ eval r message + sI
  where message = chunks bs
        sI      = fromS s
