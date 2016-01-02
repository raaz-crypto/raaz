module Generic.Utils where

import           Control.Applicative
import           Control.Monad
import qualified Data.ByteString as B
import           Data.ByteString.Internal
import           Foreign.Ptr
import           Test.Hspec


import Raaz.Core hiding (length, replicate)


with :: key -> (key -> Spec) -> Spec
with key hmsto = hmsto key


transform :: Gadget g => Base16 -> g -> IO Base16
transform inp g  = encodeByteString <$> create size (action  . castPtr)
  where size  = B.length src
        src   = decodeFormat inp
        bytes = BYTES size
        action cptr = do
          void $ fillBytes bytes src cptr
          apply g (atMost bytes) cptr

shortened :: String -> String
shortened x | l <= 11    = paddedx
            | otherwise  = prefix ++ "..." ++ suffix
  where l = length x
        prefix = take  4 x
        suffix = drop (l - 4) x
        paddedx = x ++ replicate (11 - l) ' '
