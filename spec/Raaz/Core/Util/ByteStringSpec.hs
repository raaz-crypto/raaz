module Raaz.Core.Util.ByteStringSpec where

import Prelude hiding (length, take)
import Control.Applicative
import Data.ByteString.Internal(create, createAndTrim)
import Data.ByteString (pack, ByteString, length, take)
import Foreign.Ptr
import Test.Hspec
import Test.QuickCheck


import           Raaz.Core (BYTES(..))
import qualified Raaz.Core.Util.ByteString as B

import Arbitrary

genBS :: Gen ByteString
genBS = pack <$> arbitrary

genBS' :: Gen (ByteString, Int)
genBS' = do bs <- genBS
            l  <- choose (0, length bs)
            return (bs, l)

spec :: Spec
spec = do context "unsafeCopyToCryptoPtr" $
            it "creates from a pointer, the same byte string that was copied"
            $ feed genBS $ \ bs -> (==bs) <$> clone bs

          context "unsafeNCopyToCryptoPtr"
            $ it "creates form a pointer, the same prefix of the string that was copied"
            $ feed genBS' $ \ (bs,n) -> (==) (take n bs) <$> clonePrefix (bs,n)

          context "createFrom"
            $ it "reads exactly the same bytes from the byte string pointer"
            $ feed genBS $ \ bs -> (==bs) <$> readFrom bs

    where clone       bs     = create (length bs) $ B.unsafeCopyToCryptoPtr bs . castPtr
          clonePrefix (bs,n) = createAndTrim (length bs) $ \ cptr -> do
                                   B.unsafeNCopyToCryptoPtr (BYTES n) bs $ castPtr cptr
                                   return n
          readFrom bs        = B.withByteString bs $ B.createFrom (B.length bs)
