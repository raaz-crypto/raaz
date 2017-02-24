Introduction
------------

This command supports a generalised version of
sha1sum/sha256sum/sha512sum programs that are available on a standard
linux system. It supports generating checksum files and verifying them
for all the hashes exposed by the raaz library. The purpose of writing
this application is the following.

1. To give an example of of a non-trivial program written to use the
   raaz library.

2. To make sure that the implementations of hashes in this library are
   not too off in terms of performance.

The command line options of this command is similar to that of sha1sum
and hence can be used as a replacement.

This file is a literate haskell file and hence can be compiled
directly. The text is in markdown and hence you should be able to
produce the documentation for

We start by enabling some pragmas and importing some stuff which can
be ignored.

> {-# LANGUAGE GADTs           #-}
> {-# LANGUAGE RankNTypes      #-}
> {-# LANGUAGE RecordWildCards #-}
> {-# LANGUAGE ConstraintKinds #-}

> module Command.Checksum ( checksum ) where
>
> import Control.Applicative
> import Control.Monad
> import Data.List             (intercalate)
> import Data.Monoid
> import Data.String
> import Data.Version          (showVersion)
> import System.Environment
> import System.Exit
> import System.IO             (stdin, stderr, hPutStrLn)
> import System.Console.GetOpt

> import Raaz     hiding (Result)
> import Raaz.Hash.Sha1


Verification Tokens
-------------------

Programs like sha1sum is typically used to verify that the contents of
a set of files have not been modified or corrupted. This program does
the following:

1. In compute mode it computes a set of verification tokens which
   uniquely identify the contents of the file.

2. In verification mode it takes a set of tokens are verify them.

Verification tokens are computed using the cryptographic hash. We
allow the use of any of the hashes exposed by the raaz library. Thus
for us, any hash that satisfies the constraint `TokenHash` should be
usable in computing and verifying tokens.


> type TokenHash h = (Hash h, Recommendation h, Show h, IsString h)
>

The verification token is defined below. To make it opaque, we
existentially quantify over the underlying digest.

>
> data Token  = forall h . TokenHash h
>             => Token { tokenFile    :: FilePath
>                      , tokenDigest  :: h
>                      }
>


A token can be verified easily. First we define the result type

> type Result = Either FilePath FilePath
>
> verify :: Token -> IO Result
> verify (Token{..}) = do c <- (==tokenDigest) <$> hashFile tokenFile
>                         return $ if c then Right tokenFile else Left tokenFile


Computing tokens.
-----------------

To compute the verification token, we need a way to specify the
algorithm.  The following proxy helps us in this.

> data Algorithm h   = Algorithm

Here `h` varies over all the hashes supported by the library. We now
need an easy way to tabulate all the hash algorithm that we
support. Existential types comes to the rescue once more.

> data SomeAlgorithm = forall h . TokenHash h => SomeAlgorithm (Algorithm h)

Here is the table of algorithms that we support currently.

> algorithms :: [(String, SomeAlgorithm)]
> algorithms =  [ ("broken-sha1"  , SomeAlgorithm (Algorithm :: Algorithm SHA1)   )
>               , ("sha256", SomeAlgorithm (Algorithm :: Algorithm SHA256) )
>               , ("sha512", SomeAlgorithm (Algorithm :: Algorithm SHA512) )
>               -- Add new algorithms here.
>               ]

We now define the computation function. There are two variants, one for arbitrary files
and the other for standard input.

> -- | Compute the token using a given algorithm.
> token :: TokenHash h
>       => Algorithm h  -- ^ The hashing algorithm to use.
>       -> FilePath     -- ^ The file to compute the token for.
>       -> IO Token
> token algo fp = Token fp <$> hashIt algo
>   where hashIt :: TokenHash h => Algorithm h -> IO h
>         hashIt _ = hashFile fp
>
> tokenStdin :: TokenHash h => Algorithm h -> IO Token
> tokenStdin algo = Token "-" <$> hashIt algo
>   where hashIt :: TokenHash h => Algorithm h -> IO h
>         hashIt _ = hashSource stdin
>


Printed form of tokens
----------------------

To inter-operate with programs like sha1sum, we follow the same
printed notation. The appropriate show instances for token is the
following. The format is `line := digest space mode filename`. The mode
has something to do with whether it is binary or text (we always put
a space for it).

> instance Show Token where
>   show (Token{..}) = show tokenDigest ++ "  " ++ tokenFile

We also define the associated parsing function which has to take the
the underlying algorithm as a parameter.

> parse :: TokenHash h => Algorithm h -> String -> Token
> parse algo str = Token { tokenFile   = drop 2 rest
>                        , tokenDigest = parseDigest algo digest
>                        }
>   where parseDigest    :: TokenHash h => Algorithm h -> String -> h
>         parseDigest _  = fromString
>         (digest, rest) = break (==' ') str -- break at the space.


The main function.
------------------

The overall structure of the code is clear the details follow.

> checksum :: [String] -> IO ()
> checksum =  parseOpts >=> handleArgs

> handleArgs :: (Options, [FilePath])
>            -> IO ()
> handleArgs (opts@Options{..}, files) = do
>   when optHelp printHelp       -- When the help option is given print it and exit
>   flip (either badAlgorithm) optAlgo $ \ algo -> do
>     if optCheck  -- if asked to check.
>       then verifyMode opts  algo files >>= optPrintCount
>       else computeMode      algo files


> badAlgorithm :: String -> IO ()
> badAlgorithm name = errorBailout ["Bad hash algorithm " ++ name]


The compute mode.
-----------------

There are two important modes of operation for this program, _the
compute mode_ and the _verify mode_. In the compute mode, we are given
an a set of files and we need to print out the verification tokes for
those files.

> computeMode :: SomeAlgorithm  -- The algorithm to use
>             -> [FilePath]     -- files for which tokes need to be
>                               -- computed.
>             -> IO ()
> computeMode (SomeAlgorithm algo) files
>   | null files = tokenStdin algo >>= print  -- No files means compute it for stdin.
>   | otherwise  = mapM_ printToken files     -- Print the token for each file.
>   where printToken = token algo >=> print


The verification mode of the algorithm is a bit more complicated than
the compute mode. Given a list of tokens let us first read
them. Recall the tokens are listed, one per line with the digest
followed by a space followed by the filename.


> verifyMode :: Options
>            -> SomeAlgorithm
>            -> [FilePath]
>            -> IO Int
> verifyMode (Options{..}) algo files = verifyFiles algo files >>= foldM fldr (0 :: Int)
>   where fldr n = either whenFailed whenOkey
>           where whenOkey    :: FilePath -> IO Int
>                 whenOkey    = optOkey   >=> const (return n)     -- when okey do the okey action and keep the count
>                 whenFailed  = optFailed >=> const (return (n+1)) -- when failed do the failed action and increment

This function verify the token list given in a list of files. Each
file contains a list of tokens and each of these tokens have to be
verified.

> verifyFiles :: SomeAlgorithm
>             -> [FilePath]
>             -> IO [Result]
>
> verifyFiles (SomeAlgorithm algo) files
>   | null files = getContents >>= verifyTokenList
>   | otherwise  = concat <$> mapM verifyFile files
>   where
>     verifyFile      = readFile >=> verifyTokenList
>     verifyTokenList = mapM mapper . lines
>     mapper          = verify . parse algo


This function prints the help for the program.

> printHelp :: IO ()
> printHelp = do putStrLn $ usage []
>                exitSuccess


Command line parsing
--------------------

The options supported by the program is given by the following data
type. Fields should be self explanatory.

> data Options =
>   Options { optHelp    :: Bool
>           , optCheck   :: Bool
>           , optAlgo    :: Either String SomeAlgorithm
>           , optOkey    :: FilePath -> IO () -- ^ handle successful tokens
>           , optFailed  :: FilePath -> IO () -- ^ handle failed tokens.
>           , optPrintCount   :: Int -> IO () -- ^ print failure counts.
>           }


The default options for the command is as follows.

> defaultOpts =
>   Options { optHelp       = False
>           , optCheck      = False
>           , optAlgo       = Right sha512Algorithm
>           , optOkey       = \ fp -> putStrLn (fp ++ ": OK")
>           , optFailed     = \ fp -> putStrLn (fp ++ ": FAILED")
>           , optPrintCount = printCount
>           }
>   where sha512Algorithm = SomeAlgorithm (Algorithm :: Algorithm SHA512)
>         printCount n  = when (n > 0) $ do
>           putStrLn $ show n ++ " failures."
>           exitFailure
>

We use the getOpts library to parse the command lines.  The options
are summarised in the following list. The `Endo` monoid helps in
summarising the changes to the option set.

> options :: [OptDescr (Endo Options)]
> options =
>   [ Option ['h'] ["help"]    (NoArg setHelp)    "print the help"
>   , Option ['c'] ["check"]   (NoArg setCheck)   "check instead of compute"
>   , Option ['q'] ["quiet"]   (NoArg setQuiet)   "print failure only"
>   , Option ['s'] ["status"]  (NoArg setStatusOnly)
>     "no output only return status"
>   , Option ['a'] ["algo"]    (ReqArg setAlgo "HASH")
>     $ "hash algorithm to use " ++ "[" ++ algOpts ++ "]. Default sha512"
>   ]
>   where setHelp      = Endo $ \ opt -> opt { optHelp    = True }
>         setCheck     = Endo $ \ opt -> opt { optCheck   = True }
>         setAlgo  str = Endo $ \ opt -> opt { optAlgo    = a    }
>                  where a = maybe (Left str) Right $ lookup str algorithms
>         algOpts          = intercalate "|" $ map fst algorithms
>         setQuiet      = Endo $ \ opt ->  opt { optOkey   = noPrint }
>         setStatusOnly = Endo $ \ opt ->  opt { optFailed      = noPrint
>                                              , optOkey        = noPrint
>                                              , optPrintCount  = returnStatus
>                                              }
>         noPrint           = const $ return ()
>         returnStatus n
>           | n > 0         = exitFailure
>           | otherwise     = exitSuccess
>



The usage message for the program.

> usage :: [String] -> String
> usage errs
>       | null errs = usageInfo header options
>       | otherwise = "raaz checksum: " ++ unlines errs ++ usageInfo header options
>   where header ="Usage: raaz checksum [OPTIONS] FILE1 FILE2 ..."


Parsing the options.

> parseOpts :: [String] -> IO (Options, [FilePath])
> parseOpts args = case getOpt Permute options args of
>                    (o,n,[])   -> return (appEndo (mconcat o) defaultOpts, n)
>                    (_,_,errs) -> errorBailout errs

Bail out with an error message.

> errorBailout :: [String]-> IO a
> errorBailout errs = do
>   hPutStrLn stderr $ usage errs
>   exitFailure
