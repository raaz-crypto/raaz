{-# LANGUAGE ForeignFunctionInterface #-}

-- | This module gives functions that check at runtime whether the
-- underlying cpu supports given features. CPU features are
-- architecture specific. However, functions from this module are
-- guaranteed to be defined always -- they return `False` for
-- incompatible architecture. For example, the flag `avx2` is relevant
-- only for a an X86 architecture. So it is defined false, for say the
-- ARM architecture.

module Raaz.Core.CpuSupports
       ( sse, sse2, sse3
       , sse4_1, sse4_2
       , avx, avx2
       ) where

import Foreign.C

foreign import ccall unsafe "raaz_supports_sse"
  c_sse :: IO CInt

foreign import ccall unsafe "raaz_supports_sse2"
  c_sse2 :: IO CInt

foreign import ccall unsafe "raaz_supports_sse3"
  c_sse3 :: IO CInt


foreign import ccall unsafe "raaz_supports_sse4_1"
  c_sse4_1 :: IO CInt


foreign import ccall unsafe "raaz_supports_sse4_2"
  c_sse4_2 :: IO CInt

foreign import ccall unsafe "raaz_supports_avx"
  c_avx :: IO CInt

foreign import ccall unsafe "raaz_supports_avx2"
  c_avx2 :: IO CInt


{-# NOINLINE gccBuiltInToBool #-}

gccBuiltInToBool :: IO CInt -> IO Bool
gccBuiltInToBool = fmap (>0)

-- | Check whether the cpu supports sse extension.
sse :: IO Bool
sse = gccBuiltInToBool c_sse

-- | Check whether the cpu supports sse2 extension.
sse2 :: IO Bool
sse2 = gccBuiltInToBool c_sse2

-- | Check whether the cpu supports sse3 extension.
sse3 :: IO Bool
sse3 = gccBuiltInToBool c_sse3

-- | Check whether the cpu supports sse4_1 extension.
sse4_1 :: IO Bool
sse4_1 = gccBuiltInToBool c_sse4_1

-- | Check whether the cpu supports sse-4.2 extension.
sse4_2 :: IO Bool
sse4_2 = gccBuiltInToBool c_sse4_2

-- | Check whether the cpu supports avx extension.
avx :: IO Bool
avx = gccBuiltInToBool c_avx

-- | Check whether the cpu supports avx2 extension.
avx2 :: IO Bool
avx2 = gccBuiltInToBool c_avx2
