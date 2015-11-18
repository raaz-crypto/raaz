module Generic.Cipher where

import Control.Monad
import Data.ByteString          as B
import Data.ByteString.Internal as BI
import Foreign.Ptr
import Foreign.Storable
import System.IO.Unsafe

import Raaz.Core

withReference :: CryptoPrimitive prim => prim -> Key prim -> (Reference prim -> IO a) -> IO a
withReference prim action = withGadget action

encrypt :: (CryptoPrimitive prim, Encodable a, Encodable b) => prim -> Key prim -> a -> b
encrypt prim k a = unsafePerformIO $ fmap unsafeFromByteString $ withReference prim k $ unsafeTransform (toByteString a)


unsafeTransform :: Gadget g => ByteString -> g -> IO ByteString
unsafeTransform src g = create size (action  . castPtr)
  where size  = B.length src
        bytes = BYTES size
        action cptr = do
          void $ fillBytes bytes src cptr
          apply g (atMost bytes) cptr
