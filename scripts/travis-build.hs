-- | This scripts parses cabal files of different raaz packages and
-- installs all the packages in linear fashion by resolving
-- dependencies programmatically.

import           Control.Applicative
import           Control.Exception
import           Data.List
import           Data.Maybe
import           Distribution.Package
import           Distribution.PackageDescription
import           Distribution.PackageDescription.Parse
import           Distribution.Text
import           Distribution.Verbosity
import           System.Environment
import           System.Exit
import           System.FilePath
import           System.Directory
import           System.Process

-------------------- Configuration ------------------------

-- | All the packages to be installed.
allPackages :: [String]
allPackages = [ "raaz"
              , "raaz-benchmarks"
              , "raaz-cipher"
              , "raaz-core"
              , "raaz-hash"
              , "raaz-modular"
              , "raaz-random"
              , "raaz-ssh"
              ]


-- | Relative path to the platform cabal file
platformCabal :: String -> FilePath
platformCabal p = "platform" </> "cabal" </> p <.> "cabal"

-- | Relative path to the package cabal file
packageCabal  :: String -> FilePath
packageCabal pkg = pkg </> pkg <.> "cabal"

------------------------ Main code --------------------------------

-- | The main routine which gets all the parsed results from cabal
-- files of packages and then resolve dependencies to get a linear
-- list of packages which is then installed.
main :: IO ()
main = do tEnv      <- getTravisEnv
          packages  <- raazInstallOrder
          travisMain tEnv packages >>= exitWith

travisMain :: TravisEnv -> [String] -> IO ExitCode
travisMain tEnv packages = getArgs >>= \ args ->
  case args of
    []          -> error "Empty argument list"
    (cmd:cargs) -> fastFail $ runCabal tEnv cmd cargs `map` packages

-- | Execute the actions and fail at the first instance of a failure.
fastFail :: [IO ExitCode] -> IO ExitCode
fastFail []     = return ExitSuccess
fastFail (x:xs) = x >>= \ status ->
  case status of
    ExitFailure _ -> return status
    _             -> fastFail xs

-- | Build a single package with a command line argument.
runCabal :: TravisEnv -- ^ Travis environment
         -> String    -- ^ Cabal command
         -> [String]  -- ^ cabal arguments
         -> String    -- ^ package
         -> IO ExitCode
runCabal tEnv cmd args pkg = inDirectory pkg doCmd
                               <!> unwords [cmd, pkg]
  where doCmd = case cmd of
          "install" -> install tEnv
          _         -> cabal cmd args

------------------- Travis environment processing -------------------

-- | Travis Environment given by HASKELL_PLATFORM and PARALLEL_BUILDS
-- environment variables set alongwith their corresponding
-- constraints.
data TravisEnv = TravisEnv { haskellPlatform    :: Maybe String
                           , parallelBuilds     :: Bool
                           , installConstraints :: [Dependency]
                           } deriving (Eq, Show)


-- | Get Travis Environment.
getTravisEnv :: IO TravisEnv
getTravisEnv =
  do context <- getEnvironment
     let hp    = lookup "HASKELL_PLATFORM" context
         pb    = lookup "PARALLEL_BUILDS"  context
       in do
       ct <- maybe (return []) getConstraint hp
       return TravisEnv { haskellPlatform    = hp
                        , parallelBuilds     = yesOrNo pb
                        , installConstraints = ct
                        }
  where getConstraint = fmap getDependencies . descr
        descr         = parseCabal . platformCabal
        yesOrNo       = maybe False (=="yes")



-------------------- Cabal command --------------------------

cabal :: String   -- ^ cabal command
      -> [String] -- ^ arguments.
      -> IO ExitCode
cabal cmd args = rawSystem "cabal" $ cmd : args

install :: TravisEnv -> IO ExitCode
install tenv =  cabal "install" depsOpts <!> "Installing dependencies"
             >> cabal "install" ["--enable-documentation"]
    where depsOpts     =  ["--only-dependencies"]
                       ++ ["-j" | parallelBuilds tenv ]
                       ++ map cons (installConstraints tenv)

          cons (Dependency pn vr) = "--constraint="
                                  ++ show (disp pn)
                                  ++ show (disp vr)

----------------------- Helpers for running commands ----------------

(<!>) :: IO ExitCode -> String -> IO ExitCode
(<!>) action msg = do putStrLn startMsg
                      exitCode <- action
                      case exitCode of
                        ExitSuccess -> putStrLn doneMsg
                        _           -> putStrLn failedMsg
                      return exitCode
                   where startMsg  = unwords [msg, "started"]
                         doneMsg   = unwords [msg, "done"   ]
                         failedMsg = unwords [msg, "failed" ]

inDirectory :: FilePath -> IO a -> IO a
inDirectory dir action = bracket getCurrentDirectory
                                 setCurrentDirectory
                                 actionInside
  where actionInside _ = setCurrentDirectory dir >> action

---------------------- Package dependency handling ------------------

-- | The installation order for raaz packages
raazInstallOrder :: IO [String]
raazInstallOrder = do
  deps   <- mapM raazDependency allPackages
  return $ resolve $ zip allPackages deps

-- | Compute the dependency of a single raaz package.
raazDependency :: String -> IO [String]
raazDependency pkg  = filterOut <$> dependency
  where filterOut   = delete pkg . intersect allPackages
        dependency  = getDependencyList <$> descr
        descr       = parseCabal $ packageCabal pkg

-- | Take the dependency map and provide a linear list of packages in
-- topological order.
resolve :: Eq a => [(a, [a])] -> [a]
resolve = resolve' []
  where resolve' scheduled []   = scheduled
        resolve' scheduled deps = resolve' (scheduled ++ doNow)
                                $ filter unmet deps
          where doNow   = map fst $ filter met deps
                unmet d = fst d `notElem` doNow
                met   d = null $ snd d \\ scheduled

--------------------- Some cabal functions ---------------------

-- | Get package names of the dependencies.
getDependencyList :: GenericPackageDescription -> [String]
getDependencyList = map mapFn . getDependencies
  where mapFn (Dependency name _) = show $ disp name

-- | Get the dependencies in a particular cabal file.
getDependencies :: GenericPackageDescription -> [Dependency]
getDependencies gdescr =       libDeps
                       `union` testDeps
                       `union` bmarkDeps
                       `union` exeDeps
  where libDepsMaybe = condTreeToDependency <$> condLibrary gdescr
        exeDeps      = sectionDeps           $  condExecutables gdescr
        testDeps     = sectionDeps           $  condTestSuites gdescr
        bmarkDeps    = sectionDeps           $  condBenchmarks gdescr
        libDeps      = fromMaybe [] libDepsMaybe
        --
        -- helpers
        --
        condTreeToDependency (CondNode _ deps _) = deps
        sectionDeps = foldl union [] . map  (condTreeToDependency . snd)

-- | To parse a cabal file
parseCabal :: FilePath -> IO GenericPackageDescription
parseCabal = readPackageDescription silent
