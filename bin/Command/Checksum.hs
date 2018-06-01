{-# LANGUAGE GADTs              #-}
{-# LANGUAGE RankNTypes         #-}
{-# LANGUAGE RecordWildCards    #-}
{-# LANGUAGE ConstraintKinds    #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE CPP                #-}

module Command.Checksum ( checksum )  where

import Control.Monad
import Data.Char                ( toLower )
import Data.Monoid
import Data.String
import Options.Applicative
import Raaz.Hash
import System.Exit
import System.IO


------------------------- Supported checksum algorithm -------------------------------

-- You can add new hash algorithms by adding a constructor for the
-- GADT, Algorithm h. You should also enable the command by adding a mkCmd line in the checksum


checksum :: Parser (IO ())
#if MIN_VERSION_optparse_applicative(0,13,0)
checksum = subparser $ commandGroup "Checksum Computation"
#else
checksum = subparser $ mempty
#endif
           <> metavar "CHECKSUM"
           <> mkCmd Blake2b
           <> mkCmd Blake2s
           <> mkCmd Sha512
           <> mkCmd Sha256
           -- Add the mkCmd here and also add an appropriate
           -- constructor for the Algorithm type. If you add a hash
           -- Foo then the associated command will be foosum.

-- | The hash algorithm to use.
data Algorithm h  where
  Blake2b  :: Algorithm BLAKE2b
  Blake2s  :: Algorithm BLAKE2s
  Sha256   :: Algorithm SHA256
  Sha512   :: Algorithm SHA512
  -- Add new hash algorithm here.


deriving instance Show (Algorithm h)
           -- Add a mkCmd here for the new hash algorithm

mkCmd :: SupportedHash h => Algorithm h -> Mod CommandFields (IO ())
mkCmd algo = command cmd inf
  where inf = info (helper <*> opts) $ fullDesc <> hdr <> desc
        opts     = run algo <$> optParse
        algoname = map toLower $ show algo
        cmd      = algoname ++ "sum"
        hdr      = header $ unwords [ "raaz", cmd, "- File checksums using", algoname]
        desc     = progDesc $ "compute/verify the file checksums using " ++ algoname


------------------------ Types and constriants -------------------------------------


-- | This constraint class consolidates the constraints on the checksum algorithms.
type SupportedHash h = (Hash h, Eq h, Show h, IsString h)



data Option = Option { checkChecksum :: Bool -- ^ true if we need verification.
                     , reportOkey    :: Bool -- ^ whether to print success
                     , reportFailure :: Bool -- ^ whether to print failure
                     , inputFiles    :: [FilePath]
                     }

--------------------- The checksum type ----------------------------------------

data Checksum h  = Checksum {filePath :: FilePath, fileChecksum  :: h}


instance Show h => Show (Checksum h) where
  show (Checksum{..}) = show fileChecksum ++ "  " ++ filePath

parse :: SupportedHash h => Algorithm h -> String -> Checksum h
parse algo inp = Checksum { filePath   = drop 2 rest
                          , fileChecksum = parseChecksum algo digest
                          }
  where parseChecksum    :: SupportedHash h => Algorithm h -> String -> h
        parseChecksum _  = fromString
        (digest, rest) = break (==' ') inp -- break at the space.

-- | Parse the lines into checksum.
parseMany :: SupportedHash h => Algorithm h -> String -> [Checksum h]
parseMany algo = map (parse algo) . lines

---------- The main combinators that does the actual work -------------

-- | The workhorse for this command.
run :: SupportedHash h => Algorithm h -> Option -> IO ()
run algo opt@(Option{..})
  | checkChecksum = runVerify algo opt
  | otherwise   = runCompute algo inputFiles


--------------------------- Compute mode ---------------------------------------

runCompute :: SupportedHash h
           => Algorithm h    -- Algorithm to use
           -> [FilePath]     -- files for which checksums need to be computed.
           -> IO ()
runCompute algo files
  | null files = computeStdin algo >>= print  -- No files means compute it for stdin.
  | otherwise  = mapM_ printToken files       -- Print the token for each file.
  where printToken = compute algo >=> print



-- | Compute the checksum of a file.
compute :: SupportedHash h
        => Algorithm h  -- ^ The hashing algorithm to use.
        -> FilePath     -- ^ The file to compute the token for.
        -> IO (Checksum h)
compute _ fp = Checksum fp <$> hashFile fp


-- | Compute the checksum of standard input
computeStdin :: SupportedHash h => Algorithm h -> IO (Checksum h)
computeStdin _ = Checksum "-" <$> hashSource stdin

----------------------------------- Verify Mode ---------------------------------------

runVerify :: SupportedHash h => Algorithm h -> Option -> IO ()
runVerify algo opt@(Option{..}) = do
  nFails <- if null inputFiles then getContents >>= verifyLines
            else sum <$> mapM verifyFile inputFiles

  when reportFailure $ putStrLn $ show nFails ++ " failures."
  when (nFails > 0)  exitFailure
  where
    verifyLines     = verifyList opt . parseMany algo
    verifyFile fp   = withFile fp ReadMode $ hGetContents  >=> verifyLines


verify :: SupportedHash h
       => Option
       -> Checksum  h
       -> IO Bool
verify (Option{..}) (Checksum{..}) = do
  digest <- hashFile filePath
  let result = digest == fileChecksum
      okey   = when reportOkey    $ putStrLn $ filePath ++ ": OK"
      failed = when reportFailure $ putStrLn $ filePath ++ ": FAILED"
    in do if result then okey else failed
          return result

verifyList :: SupportedHash h
           => Option
           -> [Checksum h]
           -> IO Int
verifyList opt   = fmap countFailures . mapM (verify opt)
  where countFailures = Prelude.length . filter not


----------------------------- Option parsers ----------------------------------

optParse   :: Parser Option
optParse  =  verbosityOpt <*> (Option <$> checkOpt <*> pure True <*> pure True <*> files)

  where checkOpt = switch
                   $  long "check"
                   <> short 'c'
                   <> help "Verify the input checksums instead of compute"
        files = many $ argument str $ metavar "FILE.."


verbosityOpt :: Parser (Option -> Option)
verbosityOpt = (.) <$> statusOpt <*> quietOpt
  where statusOnly opt = opt { reportOkey = False, reportFailure = False }
        quietMode  opt = opt { reportOkey = False }

        statusOpt = flag id statusOnly
                    $  short 's'
                    <> long  "status"
                    <> help "Do not print anything, only return the verification status"

        quietOpt  = flag id quietMode
                    $  short 'q'
                    <> long "quite"
                    <> help "Do not print OK, print only failures"
