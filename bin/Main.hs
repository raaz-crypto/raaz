{-# LANGUAGE RecordWildCards #-}
--
-- The main function that drives other commands.
--

import Control.Monad
import Data.Version          (showVersion)
import Data.Monoid
import Raaz                  (version)
import System.Console.GetOpt
import System.Environment



import qualified Usage  as U
import           Command.Checksum
import           Command.Rand


-- The commands know to raaz executable.
commands :: [(String, [String] -> IO ())]
commands = [ ("checksum", checksum)
           , ("rand"    , rand    )
           ]



----------------- Command line parsing -------------------------------------

data Options = Options { optVersion :: Bool
                       , optHelp    :: Bool
                       }

defaultOpts :: Options
defaultOpts = Options { optVersion    = False, optHelp  = False }

options :: [OptDescr (Endo Options)]
options = [ Option ['v'] ["version"] (NoArg setVersion) "print the version"
          , Option ['h'] ["help"]    (NoArg setHelp)    "print the help"
          ]
  where setVersion   = Endo $ \ opt -> opt { optVersion = True }
        setHelp      = Endo $ \ opt -> opt { optHelp    = True }


-- | parse options
parseOpts :: [String] -> IO Options
parseOpts args = case getOpt Permute options args of
  (o,[],[])  -> return $ appEndo (mconcat o) defaultOpts
  (_,_,errs) -> errorBailout errs




---------------------- The main function and stuff ------------------------------

main :: IO ()
main = do args <- getArgs
          case args of
            (c:restArgs) -> maybe (noCommand args) (runCmd restArgs) $ lookup c commands
            _ -> errorBailout ["empty command line"]
     where runCmd    = flip ($)
           noCommand = parseOpts >=> run

run :: Options -> IO ()
run (Options{..}) = do
  when optVersion $ printVersion
  when optHelp    $ printHelp
  where printHelp    = putStrLn $ usage []
        printVersion = putStrLn $ "raaz: " ++ showVersion version

------------------------------ Usage and error bail out -----------------------------

-- The usage message for the program.

usage :: [String] -> String
usage = U.usage options usageHeader


-- | Bail out on error
errorBailout :: [String]-> IO a
errorBailout = U.errorBailout options usageHeader

-- | The usage header to print.
usageHeader :: String
usageHeader = unlines $ [ "Usage: raaz [COMMAND] [OPTIONS]"
                        , "       raaz [OPTIONS]"
                        , ""
                        , "Supported Commands: "
                        ] ++ cmds
  where cmds     = map (("\t"++) . fst) commands
