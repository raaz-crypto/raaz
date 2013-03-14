{-|

This program compute the sha1hash of the files listed on its command
line.  It can be uses as a drop in replacement for the sha1sum program
that is available on most Unices.

-}

{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE DeriveDataTypeable #-}

import qualified Data.ByteString.Char8 as BC
import System.IO
import System.Console.CmdArgs

import Raaz.Hash(hashFile, hash, Hash)
import Raaz.Hash.Sha
import Raaz.Util.ByteString(toHex)


data Shasum = Shasum {hashType :: String,file :: String}
                deriving (Show, Data, Typeable)

shasum :: Mode (CmdArgs Shasum)
shasum = cmdArgsMode $ Shasum { hashType = "sha1" &=
                                help "Sha hash" &=
                                typ "sha1|sha224|sha256|sha384|sha512" &=
                                name "h"
                              , file = def &=
                                argPos 0 &=
                                opt ("-" :: String) &=
                                typ "FilePath"
                              } &= summary "Shasum v0"

main :: IO ()
main = do shaArgs <- cmdArgsRun shasum
          case shaArgs of
            Shasum "sha1" fp   -> printHashText sha1 fp
            Shasum "sha224" fp -> printHashText sha224 fp
            Shasum "sha256" fp -> printHashText sha256 fp
            Shasum "sha384" fp -> printHashText sha384 fp
            Shasum "sha512" fp -> printHashText sha512 fp
            _                  -> error "Unsupported sha hash"
  where sha1   = undefined :: SHA1
        sha224 = undefined :: SHA224
        sha256 = undefined :: SHA256
        sha384 = undefined :: SHA384
        sha512 = undefined :: SHA512


computeHash :: Hash h => String -> IO h
computeHash "-" = hash stdin
computeHash fp  = hashFile fp

printHashText :: Hash h => h -> String -> IO ()
printHashText u fp = do h <- computeHash fp
                        BC.putStr $ toHex $ asTypeOf h u
                        BC.putStr "  "
                        putStrLn fp
