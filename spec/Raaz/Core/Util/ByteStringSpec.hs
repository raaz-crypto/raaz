module Raaz.Core.Util.ByteStringSpec where

import Prelude hiding (length, take)
import Control.Applicative
import Data.ByteString.Internal(create, createAndTrim)
import Data.ByteString as B
import Foreign.Ptr
import Test.Hspec
import Test.QuickCheck


import           Raaz.Core as RC

import Arbitrary

genBS :: Gen ByteString
genBS = pack <$> arbitrary

genBS' :: Gen (ByteString, Int)
genBS' = do bs <- genBS
            l  <- choose (0, B.length bs)
            return (bs, l)

spec :: Spec
spec = do context "unsafeCopyToPointer" $
            it "creates from a pointer, the same byte string that was copied"
            $ feed genBS $ \ bs -> (==bs) <$> clone bs

          context "unsafeNCopyToPointer"
            $ it "creates form a pointer, the same prefix of the string that was copied"
            $ feed genBS' $ \ (bs,n) -> (==) (take n bs) <$> clonePrefix (bs,n)

          context "createFrom"
            $ it "reads exactly the same bytes from the byte string pointer"
            $ feed genBS $ \ bs -> (==bs) <$> readFrom bs

    where clone       bs     = create (B.length bs) $ RC.unsafeCopyToPointer bs . castPtr
          clonePrefix (bs,n) = createAndTrim (B.length bs) $ \ cptr -> do
                                   RC.unsafeNCopyToPointer (BYTES n) bs $ castPtr cptr
                                   return n
          readFrom bs        = RC.withByteString bs $ RC.createFrom (RC.length bs)
