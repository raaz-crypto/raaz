{-# LANGUAGE CPP #-}
module Raaz.Core.ByteSourceSpec where

import qualified Data.ByteString as B
import           System.IO
import           System.IO.Unsafe

import           Common


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

  let genL :: [ByteString] ->  Gen (BYTES Int)
      genL bs =  fromIntegral <$> choose (0, sum $ map B.length bs)
    in describe "concatenated source" $
       prop "reading from a list is equivalent to reading from concatenation" $
       \ bs -> forAll (genL bs) $ \ n -> (B.concat <$> readResultPure n bs) == readResultPure n (B.concat bs)
