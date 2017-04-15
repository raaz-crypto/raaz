{-# LANGUAGE CPP #-}
module Raaz.Core.ByteSourceSpec where

import Common
import System.IO
import System.IO.Unsafe

readResult :: ByteSource src => BYTES Int -> src -> IO (FillResult src)
readResult n src = allocaBuffer n $ fillBytes n src

{-# NOINLINE readResultPure #-}
readResultPure :: PureByteSource src => BYTES Int -> src -> FillResult src
readResultPure n src = unsafePerformIO $ readResult n src

devNullExpectation :: Expectation

#ifdef HAVE_DEV_NULL
devNullExpectation =  withBinaryFile "/dev/null" ReadMode (readResult 0) `shouldReturn` (Exhausted 0)
#else
devNullExpectation = pendingWith "Non-posix system needs an equivalent of /dev/null"
#endif


spec :: Spec
spec = do
  describe "/dev/null" $
    it "should return Exhausted even for a read request of 0" devNullExpectation
