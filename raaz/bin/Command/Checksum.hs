{-# LANGUAGE RecordWildCards    #-}


module Command.Checksum ( checksum )  where

import Control.Monad
import Data.String
import Options.Applicative
import Raaz
import System.Exit
import System.IO


------------------------- Supported checksum algorithm -------------------------------

-- You can add new hash algorithms by adding a constructor for the
-- GADT, Algorithm h. You should also enable the command by adding a mkCmd line in the checksum


checksum :: Parser (IO ())
checksum = subparser $ mconcat [ commandGroup "File checksum"
                               , metavar "DIGEST"
                               , command "checksum" inf
                               ]
  where inf = info (helper <*> opts) $ mconcat [ fullDesc, desc]
        opts     = run <$> optParse
        desc     = progDesc $ "compute/verify file checksums using the message digest algorithm of raaz"


------------------------ Types and constriants -------------------------------------




data Option = Option { checkChecksum :: Bool -- ^ true if we need verification.
                     , reportOkey    :: Bool -- ^ whether to print success
                     , reportFailure :: Bool -- ^ whether to print failure
                     , inputFiles    :: [FilePath]
                     }

--------------------- The checksum type ----------------------------------------

data Checksum = Checksum {filePath :: FilePath, fileChecksum  :: Digest}


instance Show Checksum where
  show (Checksum{..}) = show fileChecksum ++ "  " ++ filePath

parse :: String -> Checksum
parse inp = Checksum { filePath   = drop 2 rest
                     , fileChecksum = fromString dgst
                     }
  where (dgst, rest) = break (==' ') inp -- break at the space.

-- | Parse the lines into checksum.
parseMany :: String -> [Checksum]
parseMany = map parse . lines

---------- The main combinators that does the actual work -------------

-- | The workhorse for this command.
run :: Option -> IO ()
run opt@(Option{..})
  | checkChecksum = runVerify opt
  | otherwise     = runCompute inputFiles


--------------------------- Compute mode ---------------------------------------

runCompute :: [FilePath]     -- files for which checksums need to be computed.
           -> IO ()
runCompute files
  | null files = computeStdin >>= print  -- No files means compute it for stdin.
  | otherwise  = mapM_ printToken files  -- Print the token for each file.
  where printToken = compute >=> print



-- | Compute the checksum of a file.
compute :: FilePath     -- ^ The file to compute the token for.
        -> IO Checksum
compute fp = Checksum fp <$> digestFile fp


-- | Compute the checksum of standard input
computeStdin :: IO Checksum
computeStdin = Checksum "-" <$> digestSource stdin

----------------------------------- Verify Mode ---------------------------------------

runVerify :: Option -> IO ()
runVerify opt@(Option{..}) = do
  nFails <- if null inputFiles then getContents >>= verifyLines
            else sum <$> mapM verifyFile inputFiles

  when reportFailure $ putStrLn $ show nFails ++ " failures."
  when (nFails > 0)  exitFailure
  where
    verifyLines     = verifyList opt . parseMany
    verifyFile fp   = withFile fp ReadMode $ hGetContents  >=> verifyLines


verify :: Option
       -> Checksum
       -> IO Bool
verify (Option{..}) (Checksum{..}) = do
  dgst <- digestFile filePath
  let result = dgst == fileChecksum
      okey   = when reportOkey    $ putStrLn $ filePath ++ ": OK"
      failed = when reportFailure $ putStrLn $ filePath ++ ": FAILED"
    in do if result then okey else failed
          return result

verifyList :: Option
           -> [Checksum]
           -> IO Int
verifyList opt   = fmap countFailures . mapM (verify opt)
  where countFailures = Prelude.length . filter not


----------------------------- Option parsers ----------------------------------

optParse   :: Parser Option
optParse  =  verbosityOpt <*> (Option <$> checkOpt <*> pure True <*> pure True <*> files)

  where checkOpt = switch
                   $ mconcat [ long "check"
                             , short 'c'
                             , help "Verify the input checksums instead of compute"
                             ]
        files = many $ argument str $ metavar "FILE.."


verbosityOpt :: Parser (Option -> Option)
verbosityOpt = (.) <$> statusOpt <*> quietOpt
  where statusOnly opt = opt { reportOkey = False, reportFailure = False }
        quietMode  opt = opt { reportOkey = False }

        statusOpt = flag id statusOnly
                    $ mconcat [ short 's'
                              , long  "status"
                              , help "Do not print anything, only return the verification status"
                              ]

        quietOpt  = flag id quietMode
                    $ mconcat [ short 'q'
                              , long "quite"
                              , help "Do not print OK, print only failures"
                              ]
