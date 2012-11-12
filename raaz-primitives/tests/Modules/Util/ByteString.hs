-- | Tests for the module Util.ByteString.


module Modules.Util.ByteString where

import Control.Monad
import qualified Data.ByteString as B
import Data.ByteString (ByteString)
import Data.ByteString.Internal
import Data.Word
import Foreign.Ptr (castPtr)
import Test.QuickCheck
import Test.Framework
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck(Property, Arbitrary)
import Test.QuickCheck.Monadic(run, assert, monadicIO)

import Raaz.Types(BYTES(..))
import Raaz.Util.ByteString

-- | This datatype captures a bytestring along with a number which is
-- less than the length of this bytestring.
data BoundedByteString = BoundedByteString ByteString Int deriving Show

instance Arbitrary B.ByteString where
         arbitrary = fmap B.pack arbitrary

instance Arbitrary BoundedByteString where
         arbitrary = do
           n <- choose (0,1000)
           m <- choose (n,10000)
           w <- vector m
           return $ BoundedByteString (B.pack w) n

-- | Tests storing a bytestring to a CryptoPtr using
-- unsafeCopyToCryptoPtr and reading back gives the same bytestring.
prop_unSafeCopy :: ByteString -> Property
prop_unSafeCopy bs = monadicIO $ do
  w <- run $ create (B.length bs) (unsafeCopyToCryptoPtr bs . castPtr)
  assert $ w == bs

-- | Tests storing a bytestring to a CryptoPtr using
-- unsafeNCopyToCryptoPtr and reading back gives the same bytestring.
prop_unSafeNCopy :: BoundedByteString -> Property
prop_unSafeNCopy (BoundedByteString bs n) = monadicIO $ do
  w <- run $ createAndTrim (B.length bs) $ \ ptr -> do
    unsafeNCopyToCryptoPtr (BYTES n) bs $ castPtr ptr
    return n
  assert $ B.take n bs == w

tests = [ testProperty "UnsafeCopyToCryptoPtr" prop_unSafeCopy
        , testProperty "UnsafeNCopyToCryptoPtr" prop_unSafeNCopy
        ]
