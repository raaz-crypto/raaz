import           Control.Monad
import           Criterion.Main
import qualified Blaze.ByteString.Builder                as BB
import qualified Blaze.ByteString.Builder.Internal.Write as BB

import           Data.ByteString                         ( ByteString )
import           Data.Monoid
import           Data.Word (Word32)
import           Foreign.Ptr (castPtr)

import           Raaz.Core.Types
import qualified Raaz.Core.Write  as RW
import qualified Raaz.Core.Encode as E


main :: IO ()
main = defaultMain
       [ bench "BB Write Word32s"   $ whnf blazeWriteWords word32s
       , bench "mconcat"            $ whnf raazWriteWords  word32s
       ]
  where
    n = 100000
    word32s :: [Word32]
    word32s = take n $ [1..]
    {-# NOINLINE word32s #-}


blazeWriteWords :: [Word32] -> ByteString
blazeWriteWords = BB.writeToByteString . mconcat . map BB.writeStorable

raazWriteWords :: [Word32] -> ByteString
raazWriteWords = E.toByteString . mconcat . map RW.writeStorable
