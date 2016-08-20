{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE FlexibleInstances   #-}
import           Control.Monad
import           Criterion
import           Criterion.Main
import qualified Blaze.ByteString.Builder                as BB
import qualified Blaze.ByteString.Builder.Internal.Write as BB

import           Data.ByteString                         ( ByteString )
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import           Data.Monoid
import           Data.Word
import           Foreign.Ptr (castPtr)

import           Raaz.Core.Types
import qualified Raaz.Core.Transfer  as RW
import qualified Raaz.Core.Encode as E

-- Why 4000 entries. The result size is roughly 32k which is the L1 cache
-- size. 4 * 8 bytes * 1 kilo
maxVal :: Num n => n
maxVal = 40000

ws :: [Word]
ws = [1..maxVal]

w64s :: [Word64]
w64s = [1..maxVal]

le64s :: [LE Word64]
le64s = [1..maxVal]

be64s :: [BE Word64]
be64s = [1..maxVal]

main :: IO ()
main = defaultMain
         [ bgroup "Words"
           [ bench "blaze/write"
             $ nf (blazeWrite BB.writeStorable) ws
           , bench "write"
             $ nf (raazWrite RW.writeStorable)  ws
           ]
         , bgroup "LE64s"
           [ bench "blaze/write"
             $ nf (blazeWrite BB.writeWord64le) w64s
           , bench "write"
             $ nf (raazWrite RW.write)          le64s
           ]
         , bgroup "BE64s"
           [ bench "blaze/write"
             $ nf (blazeWrite BB.writeWord64be) w64s
           , bench "write"
             $ nf (raazWrite RW.write)          be64s
           ]
         ]
blazeWrite :: (a -> BB.Write)   -> [a] -> ByteString
blazeWrite fn = BB.writeToByteString . mconcat . map fn

raazWrite  :: (a -> RW.WriteIO) -> [a] -> ByteString
raazWrite fn = E.toByteString . mconcat . map fn
