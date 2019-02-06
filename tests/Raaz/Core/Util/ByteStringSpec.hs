module Raaz.Core.Util.ByteStringSpec where

import           Tests.Core
import           Prelude hiding (length, take)
import           Data.ByteString.Internal(createAndTrim)
import qualified Data.ByteString as B
import           Foreign.Ptr

import           Raaz.Core as RC
import           Raaz.Core.Types.Internal (BYTES (..))


spec :: Spec
spec = do context "unsafeCopyToPointer" $
            it "creates the same copy at the input pointer"
            $ feed arbitrary $ \ bs -> (== bs) <$> clone bs

          let gen = do bs <- arbitrary
                       l  <- choose (0, B.length bs)
                       return (bs, l)
              in context "unsafeNCopyToPointer"
                 $ it "creates the same prefix of at the input pointer"
                 $ feed gen $ \ (bs,n) -> (==) (B.take n bs)
                                          <$> clonePrefix (bs,n)

          context "createFrom"
            $ it "reads exactly the same bytes from the byte string pointer"
            $ feed arbitrary $ \ bs -> (==bs) <$> readFrom bs

    where clone bs  = create (length bs) $ RC.unsafeCopyToPointer bs . castPtr
          clonePrefix (bs,n)
            = createAndTrim (B.length bs)
              $ \ cptr -> do RC.unsafeNCopyToPointer (BYTES n) bs
                               $ castPtr cptr
                             return n
          readFrom bs        = RC.withByteString bs
                               $ RC.createFrom (RC.length bs)
