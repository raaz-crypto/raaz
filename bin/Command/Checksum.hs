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
import Raaz
import Raaz.Hash.Sha1
import System.Exit
import System.IO


------------------------- Supported checksum algorithm -------------------------------

-- You can add new hash algorithms by adding a constructor for the
-- GADT, Algorithm h. You should also enable the command by adding a mkCmd line in the checksum


checksum :: Parser (IO ())
#if MIN_VERSION_optparse_applicative(0,14,0)
checksum = subparser $ commandGroup "Checksum Computation"
#else
checksum = subparser $ mempty
#endif
           <> mkCmd Sha1
           <> mkCmd Sha512
           <> mkCmd Sha256
           -- Add the mkCmd here and also add an appropriate
           -- constructor for the Algorithm type. If you add a hash
           -- Foo then the associated command will be foosum.

-- | The hash algorithm to use.
data Algorithm h  where
  Sha1     :: Algorithm SHA1
  Sha256   :: Algorithm SHA256
  Sha512   :: Algorithm SHA512
  -- Add new hash algorithm here.


deriving instance Show (Algorithm h)
           -- Add a mkCmd here for the new hash algorithm

mkCmd :: Digest h => Algorithm h -> Mod CommandFields (IO ())
mkCmd algo = command cmd inf
  where inf = info (helper <*> opts) $ fullDesc <> hdr <> desc
        opts     = run algo <$> optParse
        algoname = map toLower $ show algo
        cmd      = algoname ++ "sum"
        hdr      = header $ unwords [ "raaz", cmd, "- File checksums using", algoname]
        desc     = progDesc $ "Compute or verify the file checksums using " ++ algoname


------------------------ Types and constriants -------------------------------------


-- | This constraint class consolidates the constraints on the checksum algorithms.
type Digest h = (Hash h, Recommendation h, Show h, IsString h)



data Option = Option { checkDigest   :: Bool -- ^ true if we need verification.
                     , reportOkey    :: Bool -- ^ whether to print success
                     , reportFailure :: Bool -- ^ whether to print failure
                     , inputFiles    :: [FilePath]
                     }

--------------------- The checksum type ----------------------------------------

data Checksum h  = Checksum {filePath :: FilePath, fileDigest  :: h}


instance Show h => Show (Checksum h) where
  show (Checksum{..}) = show fileDigest ++ "  " ++ filePath

parse :: Digest h => Algorithm h -> String -> Checksum h
parse algo inp = Checksum { filePath   = drop 2 rest
                          , fileDigest = parseDigest algo digest
                          }
  where parseDigest    :: Digest h => Algorithm h -> String -> h
        parseDigest _  = fromString
        (digest, rest) = break (==' ') inp -- break at the space.

-- | Parse the lines into checksum.
parseMany :: Digest h => Algorithm h -> String -> [Checksum h]
parseMany algo = map (parse algo) . lines

---------- The main combinators that does the actual work -------------

-- | The workhorse for this command.
run :: Digest h => Algorithm h -> Option -> IO ()
run algo opt@(Option{..})
  | checkDigest = runVerify algo opt
  | otherwise   = runCompute algo inputFiles


--------------------------- Compute mode ---------------------------------------

runCompute :: Digest h
           => Algorithm h    -- Algorithm to use
           -> [FilePath]     -- files for which checksums need to be computed.
           -> IO ()
runCompute algo files
  | null files = computeStdin algo >>= print  -- No files means compute it for stdin.
  | otherwise  = mapM_ printToken files       -- Print the token for each file.
  where printToken = compute algo >=> print



-- | Compute the checksum of a file.
compute :: Digest h
        => Algorithm h  -- ^ The hashing algorithm to use.
        -> FilePath     -- ^ The file to compute the token for.
        -> IO (Checksum h)
compute _ fp = Checksum fp <$> hashFile fp


-- | Compute the checksum of standard input
computeStdin :: Digest h => Algorithm h -> IO (Checksum h)
computeStdin _ = Checksum "-" <$> hashSource stdin

----------------------------------- Verify Mode ---------------------------------------

runVerify :: Digest h => Algorithm h -> Option -> IO ()
runVerify algo opt@(Option{..}) = do
  nFails <- if null inputFiles then getContents >>= verifyLines
            else sum <$> mapM verifyFile inputFiles

  when reportFailure $ putStrLn $ show nFails ++ " failures."
  when (nFails > 0)  exitFailure
  where
    verifyLines     = verifyList opt . parseMany algo
    verifyFile fp   = withFile fp ReadMode $ hGetContents  >=> verifyLines


verify :: Digest h
       => Option
       -> Checksum  h
       -> IO Bool
verify (Option{..}) (Checksum{..}) = do
  digest <- hashFile filePath
  let result = digest == fileDigest
      okey   = when reportOkey    $ putStrLn $ filePath ++ ": OK"
      failed = when reportFailure $ putStrLn $ filePath ++ ": FAILED"
    in do if result then okey else failed
          return result

verifyList :: Digest h
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
