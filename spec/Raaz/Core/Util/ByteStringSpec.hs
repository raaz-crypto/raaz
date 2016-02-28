module Raaz.Core.Util.ByteStringSpec where

import Common
import Prelude hiding (length, take)
import Data.ByteString.Internal(create, createAndTrim)
import Data.ByteString as B
import Foreign.Ptr

import Raaz.Core as RC

genBS :: Gen ByteString
genBS = pack <$> arbitrary

genBS' :: Gen (ByteString, Int)
genBS' = do bs <- genBS
            l  <- choose (0, B.length bs)
            return (bs, l)

spec :: Spec
spec = do context "unsafeCopyToPointer" $
            it "creates the same copy at the input pointer"
            $ feed genBS $ \ bs -> (==bs) <$> clone bs

          context "unsafeNCopyToPointer"
            $ it "creates the same prefix of at the input pointer"
            $ feed genBS' $ \ (bs,n) -> (==) (take n bs)
                                        <$> clonePrefix (bs,n)

          context "createFrom"
            $ it "reads exactly the same bytes from the byte string pointer"
            $ feed genBS $ \ bs -> (==bs) <$> readFrom bs

    where clone bs           = create (B.length bs)
                               $ RC.unsafeCopyToPointer bs . castPtr
          clonePrefix (bs,n)
            = createAndTrim (B.length bs)
              $ \ cptr -> do RC.unsafeNCopyToPointer (BYTES n) bs
                               $ castPtr cptr
                             return n
          readFrom bs        = RC.withByteString bs
                               $ RC.createFrom (RC.length bs)
