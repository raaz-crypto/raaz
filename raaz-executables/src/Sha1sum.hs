{-
Provides executable to perform sha family checksums of files.
-}
{-# LANGUAGE DeriveDataTypeable #-}

import Control.Applicative
import Raaz.Hash
import Raaz.Hash.Instances ()
import Raaz.Hash.Sha
import Raaz.Util.ByteString

import qualified Data.ByteString.Char8 as BC
import System.Environment

main :: IO ()
main = do
  (fp:_) <- getArgs
  BC.putStrLn =<< toHex <$> (hashFile fp :: IO SHA1)
