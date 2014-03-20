{-# LANGUAGE FlexibleContexts #-}
module Modules.Salsa20 (benchmarks, benchmarksTiny) where

import           Criterion.Main
import           Data.ByteString          (ByteString,pack)
import qualified Data.ByteString          as BS
import           Data.Typeable

import           Raaz.Primitives
import           Raaz.Benchmark.Gadget
import           Raaz.Primitives.Cipher

import           Raaz.Cipher.Salsa20.Internal
import           Raaz.Cipher.Salsa20

import           Modules.Defaults         (nBlocks)

testKey128 :: ByteString
testKey128 =  pack [1..32]

testKey256 :: ByteString
testKey256 =  pack [1..48]


benchCipher g gname iv = benchGadgetWith g gname iv (nBlocks g)

benchmarksTiny = take 2 benchmarks

benchmarks = [ benchCipher s20_128  "Salsa20/20 KEY128 HGadget" (getCxt testKey128)
             , benchCipher cs20_128 "Salsa20/20 KEY128 CGadget" (getCxt testKey128)
             , benchCipher s12_128  "Salsa20/12 KEY128 HGadget" (getCxt testKey128)
             , benchCipher cs12_128 "Salsa20/12 KEY128 CGadget" (getCxt testKey128)
             , benchCipher s8_128  "Salsa20/8 KEY128 HGadget" (getCxt testKey128)
             , benchCipher cs8_128 "Salsa20/8 KEY128 CGadget" (getCxt testKey128)
             , benchCipher s20_256  "Salsa20/20 KEY256 HGadget" (getCxt testKey256)
             , benchCipher cs20_256 "Salsa20/20 KEY256 CGadget" (getCxt testKey256)
             , benchCipher s12_256  "Salsa20/12 KEY256 HGadget" (getCxt testKey256)
             , benchCipher cs12_256 "Salsa20/12 KEY256 CGadget" (getCxt testKey256)
             , benchCipher s8_256  "Salsa20/8 KEY256 HGadget" (getCxt testKey256)
             , benchCipher cs8_256 "Salsa20/8 KEY256 CGadget" (getCxt testKey256)
             ]
  where
    s20_128 :: HGadget (Cipher (Salsa20 R20) KEY128 Encryption)
    s20_128 = undefined
    s20_256 :: HGadget (Cipher (Salsa20 R20) KEY256 Encryption)
    s20_256 = undefined
    s12_128 :: HGadget (Cipher (Salsa20 R12) KEY128 Encryption)
    s12_128 = undefined
    s12_256 :: HGadget (Cipher (Salsa20 R12) KEY256 Encryption)
    s12_256 = undefined
    s8_128 :: HGadget (Cipher (Salsa20 R8) KEY128 Encryption)
    s8_128 = undefined
    s8_256 :: HGadget (Cipher (Salsa20 R8) KEY256 Encryption)
    s8_256 = undefined
    cs20_128 :: CGadget (Cipher (Salsa20 R20) KEY128 Encryption)
    cs20_128 = undefined
    cs20_256 :: CGadget (Cipher (Salsa20 R20) KEY256 Encryption)
    cs20_256 = undefined
    cs12_128 :: CGadget (Cipher (Salsa20 R12) KEY128 Encryption)
    cs12_128 = undefined
    cs12_256 :: CGadget (Cipher (Salsa20 R12) KEY256 Encryption)
    cs12_256 = undefined
    cs8_128 :: CGadget (Cipher (Salsa20 R8) KEY128 Encryption)
    cs8_128 = undefined
    cs8_256 :: CGadget (Cipher (Salsa20 R8) KEY256 Encryption)
    cs8_256 = undefined
