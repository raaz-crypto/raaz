Introduction
============

This is the generalised version of sha1sum/sha256sum/sha512sum
programs that are available on a standard linux system. It supports
generating checksum files and verifying them for all the hashes
exposed by the raaz library. The purpose of writing this application
is the following.

1. To give an example of of a non-trivial program written to use the
   raaz library.

2. To make sure that the implementations in this library are not too
   off in terms of performance of the hashing implementation s

The command line options of this program is similar to that of sha1sum
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

> import Control.Applicative
> import Control.Monad
> import Data.List             (intercalate)
> import Data.String
> import Data.Version
> import System.Environment
> import System.Exit
> import System.IO             (stdin, stderr, hPutStrLn)
> import System.Console.GetOpt


> import Raaz.Core     hiding (Result)
> import Raaz.Hash
> import Raaz.Version


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

The verification is quite simple and works opaquely.

> verify :: Token -> IO Bool
> verify (Token{..}) = (==tokenDigest) <$> hashFile tokenFile



Computing Tokens.
-----------------

For computing we need to somehow get access to the underlying hash
algorithm. We should be able to specify the algorithm
to use as an argument for the computing functions.

> -- | Compute the token using a given algorithm.
> token :: TokenHash h
>       => Algorithm h  -- ^ The hashing algorithm to use.
>       -> FilePath     -- ^ The file to compute the token for.
>       -> IO Token


The algorithm data type is just a proxy which we define as follows.

> data Algorithm h   = Algorithm

Using the above proxy type we can define the token computation
function.

> token algo fp = Token fp <$> hashIt algo
>   where hashIt :: TokenHash h => Algorithm h -> IO h
>         hashIt _ = hashFile fp
>

This function computes the verification token for the standard input.

> tokenStdin :: TokenHash h => Algorithm h -> IO Token
> tokenStdin algo = Token "-" <$> hashIt algo
>   where hashIt :: TokenHash h => Algorithm h -> IO h
>         hashIt _ = hashSource stdin
>


Printed form of tokens
----------------------


To inter-operate with programs like sha1sum, we follow the same
printed notation. The appropriate show instances for token is the
following.

> instance Show Token where
>   show (Token{..}) = show tokenDigest ++ "  " ++ tokenFile

We also define the associated parsing function which has to take the
the underlying algorithm as a parameter.

> parse :: TokenHash h => Algorithm h -> String -> Token
> parse algo str      = Token { tokenFile   = drop 2 rest
>                             , tokenDigest = parseDigest algo digest
>                             }
>   where parseDigest    :: TokenHash h => Algorithm h -> String -> h
>         parseDigest _  = fromString
>         (digest, rest) = break (==' ') str



We now need an easy way to tabulate all the hash algorithm that we
support. Existential types comes to the rescue once more.

> data SomeAlgorithm = forall h . TokenHash h =>
>                      SomeAlgorithm (Algorithm h)

This is the table of algorithms that we support.  are given below.

> algorithms :: [(String, SomeAlgorithm)]
> algorithms =  [ ("sha1"  , SomeAlgorithm (Algorithm :: Algorithm SHA1)   )
>               , ("sha256", SomeAlgorithm (Algorithm :: Algorithm SHA256) )
>               , ("sha512", SomeAlgorithm (Algorithm :: Algorithm SHA512) )
>               ]

The main function.
------------------

There are two important modes of operation for this program. In the
first mode the

> computeMode :: SomeAlgorithm
>             -> [FilePath]
>             -> IO ()
> computeMode (SomeAlgorithm algo) files
>   | null files = tokenStdin algo >>= print
>   | otherwise  = mapM_ printToken files
>   where printToken = token algo >=> print


The verification mode of the algorithm.

> verifyMode :: ( FilePath -> IO () ) -- ^ What to do for success.
>            -> ( FilePath -> IO () ) -- ^ What to do for failure
>            -> ( Int      -> IO () ) -- ^ Do something with the number.
>            -> SomeAlgorithm
>            -> [FilePath]
>            -> IO ()
>
> verifyMode okey failed printCount (SomeAlgorithm algo) files
>   | null files = getContents >>= verifyInput 0 >>= result
>   | otherwise  = verifyManyFiles files >>= result
>   where
>     parseTokens       = map (parse algo) . lines
>     result n          = do printCount n
>                            if (n > 0) then exitFailure
>                              else exitSuccess
>     -- Verify a list of files
>     verifyManyFiles   = foldM verifyFile 0
>     -- Verify a single file.
>     verifyFile  n fp  = readFile fp          >>= verifyInput n
>     -- verify all the digests listed in the given argument string.
>     verifyInput n     = return . parseTokens >=> foldM verifyOne n
>     -- Verify a single token and keep track of the total number of
>     -- failures.
>     verifyOne  n tok  = do
>       status <- verify tok
>       if status then do okey   $ tokenFile tok; return n
>                 else do failed $ tokenFile tok; return (n+1)
>


The main function.
------------------

> main :: IO ()
> main =  parseOpts >>= handleArgs
>
> handleArgs :: (Options, [FilePath])
>            -> IO ()
> handleArgs (Options{..}, files) = do
>   when optHelp printHelp
>   when optVersion printVersion
>   flip (either badAlgo) optAlgo $ \ algo ->
>     if optCheck
>     then verifyMode optOkey optFailed optPrintCount algo files
>     else computeMode algo files
>   where badAlgo name = errorBailout ["Bad hash algorithm " ++ name]




This function prints the help for the program.

> printHelp :: IO ()
> printHelp = do putStrLn $ usage []
>                exitSuccess

and this prints the version information.

> printVersion :: IO ()
> printVersion = do putStrLn $ "checksum: raaz-" ++ showVersion version
>                   exitSuccess
>


Command line parsing
--------------------

We use the getOpts library to parse the command lines.  The options
are summarised in the following list.

> options :: [OptDescr (Options -> Options)]
> options =
>   [ Option ['v'] ["version"] (NoArg setVersion) "print the version"
>   , Option ['h'] ["help"]    (NoArg setHelp)    "print the help"
>   , Option ['c'] ["check"]   (NoArg setCheck)   "check instead of compute"
>   , Option ['q'] ["quiet"]   (NoArg setQuiet)   "print failure only"
>   , Option ['s'] ["status"]  (NoArg setStatusOnly)
>     "no output only return status"
>   , Option ['a'] ["algo"]    (ReqArg setAlgo "HASH")
>     $ "hash algorithm to use " ++ "(" ++ algOpts ++ ")"
>   ]
>   where setVersion opt   = opt { optVersion = True }
>         setHelp    opt   = opt { optHelp    = True }
>         setCheck   opt   = opt { optCheck   = True }
>         setAlgo  str opt = opt { optAlgo    = a    }
>                  where a = maybe (Left str) Right $ lookup str algorithms
>         algOpts          = intercalate "|" $ map fst algorithms
>         setQuiet      opt = opt          { optOkey   = noPrint }
>         setStatusOnly opt = setQuiet opt { optFailed = noPrint
>                                          , optPrintCount  = returnStatus
>                                          }
>         noPrint           = const $ return ()
>         returnStatus n
>           | n > 0         = exitFailure
>           | otherwise     = exitSuccess
>


The options data type. Fields should be self explanatory.

> data Options =
>   Options { optVersion :: Bool
>           , optHelp    :: Bool
>           , optCheck   :: Bool
>           , optAlgo    :: Either String SomeAlgorithm
>           , optOkey    :: FilePath -> IO () -- ^ handle successful tokens
>           , optFailed  :: FilePath -> IO () -- ^ handle failed tokens.
>           , optPrintCount   :: Int -> IO () -- ^ print failure counts.
>           }

The default options for the command is as follows.

> defOpts =
>   Options { optVersion    = False
>           , optHelp       = False
>           , optCheck      = False
>           , optAlgo       = Right sha1Algorithm
>           , optOkey       = \ fp -> putStrLn (fp ++ ": OK")
>           , optFailed     = \ fp -> putStrLn (fp ++ ": FAILED")
>           , optPrintCount = printCount
>           }
>   where sha1Algorithm = SomeAlgorithm (Algorithm :: Algorithm SHA1)
>         printCount n  = when (n > 0) $ do
>           putStrLn $ show n ++ " failures."

The usage message for the program.

> usage :: [String] -> String
> usage errs = "checksum: " ++ unlines errs ++ usageInfo header options
>   where header ="Usage: checksum [OPTIONS] FILE1 FILE2"

Parsing the options.

> parseOpts :: IO (Options, [FilePath])
> parseOpts = do args  <- getArgs
>                case getOpt Permute options args of
>                  (o,n,[])   -> return (foldl (flip id) defOpts o, n)
>                  (_,_,errs) -> errorBailout errs

Bail out with an error message.

> errorBailout :: [String]-> IO a
> errorBailout errs = do
>   hPutStrLn stderr $ usage errs
>   exitFailure
