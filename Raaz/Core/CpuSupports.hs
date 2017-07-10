{-# LANGUAGE ForeignFunctionInterface #-}

-- | This module gives functions that check at runtime whether the
-- underlying cpu supports given features.
module Raaz.Core.CpuSupports
       ( sse, sse2, sse3
       , sse4_1, sse4_2
       , avx, avx2
       ) where

foreign import ccall unsafe "raaz_supports_sse"
  c_sse :: Bool

foreign import ccall unsafe "raaz_supports_sse2"
  c_sse2 :: Bool

foreign import ccall unsafe "raaz_supports_sse3"
  c_sse3 :: Bool


foreign import ccall unsafe "raaz_supports_sse4_1"
  c_sse4_1 :: Bool


foreign import ccall unsafe "raaz_supports_sse4_2"
  c_sse4_2 :: Bool

foreign import ccall unsafe "raaz_supports_avx"
  c_avx :: Bool

foreign import ccall unsafe "raaz_supports_avx2"
  c_avx2 :: Bool


-- | Check whether the cpu supports sse extension.
sse :: Bool
sse = c_sse

-- | Check whether the cpu supports sse2 extension.
sse2 :: Bool
sse2 = c_sse2

-- | Check whether the cpu supports sse3 extension.
sse3 :: Bool
sse3 = c_sse3

-- | Check whether the cpu supports sse4_1 extension.
sse4_1 :: Bool
sse4_1 = c_sse4_1

-- | Check whether the cpu supports sse-4.2 extension.
sse4_2 :: Bool
sse4_2 = c_sse4_2

-- | Check whether the cpu supports avx extension.
avx :: Bool
avx = c_avx

-- | Check whether the cpu supports avx2 extension.
avx2 :: Bool
avx2 = c_avx2
