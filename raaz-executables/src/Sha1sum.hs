{-|

This program compute the sha1hash of the files listed on its command
line.  It can be uses as a drop in replacement for the sha1sum program
that is available on most Unices.

-}

{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE DeriveDataTypeable #-}

import Control.Monad(forM_)
import qualified Data.ByteString.Char8 as BC
import System.Environment(getArgs)
import System.IO(stdin)

import Raaz.Hash(hashFile, hashFileHandle, Hash)
import Raaz.Hash.Sha(SHA1)
import Raaz.Util.ByteString(toHex)


main :: IO ()
main = do args <- getArgs
          if null args then printHashText sha1 "-"
             else forM_ args $ printHashText sha1
  where sha1 = undefined :: SHA1

computeHash :: Hash h => String -> IO h
computeHash file | file == "-" = hashFileHandle stdin
                 | otherwise   = hashFile file

printHashText :: Hash h => h -> String -> IO ()
printHashText u file = do h <- computeHash file
                          BC.putStr $ toHex $ asTypeOf h u
                          BC.putStr "  "
                          putStrLn file
