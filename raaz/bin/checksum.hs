{-|

This program compute the sha1hash of the files listed on its command
line.  It can be uses as a drop in replacement for the sha1sum program
that is available on most Unices.

-}

{-# LANGUAGE OverloadedStrings  #-}
{-# LANGUAGE DeriveDataTypeable #-}

import           Control.Applicative    ( (<$>)       )
import qualified Data.ByteString.Char8  as BC
import           System.Console.CmdArgs
import           Data.Version           ( showVersion )
import           Paths_raaz             ( version     )

import Raaz.Hash
import Raaz.Core.Primitives.Hash        ( Hash        )


data CheckSum = CheckSum { hashType :: String
                         , check    :: Bool
                         , files    :: [String]
                         } deriving (Show, Data, Typeable)

checkSum :: Mode (CmdArgs CheckSum)
checkSum = cmdArgsMode $ CheckSum { hashType = "sha1" &=
                                    help "Hash Function" &=
                                    typ "sha1|sha224|sha256|sha384|sha512|blake256" &=
                                    name "h"
                                  , check = def &=
                                    help "read hash tags from file and check them"
                                  , files = def &=
                                    args &=
                                    opt ("-" :: String) &=
                                    typFile
                                  } &= summary ("checksum " ++ showVersion version)

main :: IO ()
main = do hashArgs <- cmdArgsRun checkSum
          case hashArgs of
            CheckSum "sha1"     c fp -> mapM_ (printHashText sha1File c    ) fp
            CheckSum "sha224"   c fp -> mapM_ (printHashText sha224File c  ) fp
            CheckSum "sha256"   c fp -> mapM_ (printHashText sha256File c  ) fp
            CheckSum "sha384"   c fp -> mapM_ (printHashText sha384File c  ) fp
            CheckSum "sha512"   c fp -> mapM_ (printHashText sha512File c  ) fp
            CheckSum "blake256" c fp -> mapM_ (printHashText blake256File c) fp
            _                        -> error "Unsupported hash function"

printHashText :: Hash h => (FilePath -> IO h) -> Bool -> String -> IO ()
printHashText hf False fp = do h <- hf fp
                               BC.putStr $ toHex h
                               BC.putStr "  "
                               putStrLn fp

printHashText hf True fp = do hashes <- readHashFile fp
                              mapM_ (checkAndPrint hf) hashes

-- | Reads the standard space separate `hash filepath` file and checks
-- for the correctness of hash of each file.
readHashFile :: String -> IO [(String,String)]
readHashFile fp = map readHashLine . lines <$> readFile fp
  where
    readHashLine l = case words l of
                       (h:rest) -> (h,unwords rest)
                       _        -> error "illformed hashfile"

checkAndPrint :: Hash h => (FilePath -> IO h) -> (String,String) -> IO ()
checkAndPrint hf (ht,fp) = do hs <- hf fp
                              putStr fp
                              putStrLn (if toHex hs == BC.pack ht
                                          then ": OK"
                                          else ": FAILED")
