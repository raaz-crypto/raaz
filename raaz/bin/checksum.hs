{-|

This program compute the sha1hash of the files listed on its command
line.  It can be uses as a drop in replacement for the sha1sum program
that is available on most Unices.

-}

{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE DeriveDataTypeable #-}

import Control.Applicative ((<$>))
import qualified Data.ByteString.Char8 as BC
import System.IO
import System.Console.CmdArgs
import Data.Version(showVersion)
import Paths_raaz(version)

import Raaz.Hash
import Raaz.Primitives.Hash(Hash)

import Raaz.Util.ByteString(toHex)

data Shasum = Shasum { hashType :: String
                     , check    :: Bool
                     , files     :: [String]
                     }
                deriving (Show, Data, Typeable)

shasum :: Mode (CmdArgs Shasum)
shasum = cmdArgsMode $ Shasum { hashType = "sha1" &=
                                help "Sha hash" &=
                                typ "sha1|sha224|sha256|sha384|sha512" &=
                                name "h"
                              , check = def &=
                                help "read hash tags from file and check them"
                              , files = def &=
                                args &=
                                opt ("-" :: String) &=
                                typFile
                              } &= summary ("checksum " ++ showVersion version)

main :: IO ()
main = do shaArgs <- cmdArgsRun shasum
          case shaArgs of
            Shasum "sha1"   c fp -> mapM_ (printHashText sha1 c) fp
            Shasum "sha224" c fp -> mapM_ (printHashText sha224 c) fp
            Shasum "sha256" c fp -> mapM_ (printHashText sha256 c) fp
            Shasum "sha384" c fp -> mapM_ (printHashText sha384 c) fp
            Shasum "sha512" c fp -> mapM_ (printHashText sha512 c) fp
            _                  -> error "Unsupported sha hash"
  where sha1   = undefined :: SHA1
        sha224 = undefined :: SHA224
        sha256 = undefined :: SHA256
        sha384 = undefined :: SHA384
        sha512 = undefined :: SHA512


computeHash :: Hash h => String -> IO h
computeHash "-" = sourceHash stdin
computeHash fp  = hashFile fp

printHashText :: Hash h => h -> Bool -> String -> IO ()
printHashText u False fp = do h <- computeHash fp
                              BC.putStr $ toHex $ asTypeOf h u
                              BC.putStr "  "
                              putStrLn fp

printHashText u True fp = do hf <- readHashFile fp
                             mapM_ (checkAndPrint u) hf

-- | Reads the standard space separate `hash filepath` file and checks
-- for the correctness of hash of each file.
readHashFile :: String -> IO [(String,String)]
readHashFile fp = map readHashLine . lines <$> readFile fp
  where
    readHashLine l = case words l of
                       (h:rest) -> (h,unwords rest)
                       _        -> error "illformed hashfile"

checkAndPrint :: Hash h => h -> (String,String) -> IO ()
checkAndPrint h (ht,fp) = do hs <- computeHash fp
                             putStr fp
                             case ((toHex $ hs `asTypeOf` h) == BC.pack ht) of
                               True  -> putStrLn ": OK"
                               False -> putStrLn ": FAILED"
