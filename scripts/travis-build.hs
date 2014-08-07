-- | This scripts parses cabal file of packages and installs all the packages
-- in linear fashion by resolving dependencies programmatically.

import           Control.Applicative
import           Data.List
import qualified Data.Map                              as Map
import           Data.Maybe
import qualified Data.Set                              as Set
import           Distribution.Package
import           Distribution.PackageDescription
import           Distribution.PackageDescription.Parse
import           Distribution.Text
import           Distribution.Verbosity
import           Distribution.Version
import           System.Environment
import           System.Exit
import           System.Directory
import           System.Process

-- | All the packages to be installed.
allPackages :: [PackageName]
allPackages = [ PackageName "raaz"
              , PackageName "raaz-benchmarks"
              , PackageName "raaz-cipher"
              , PackageName "raaz-core"
              , PackageName "raaz-hash"
              , PackageName "raaz-modular"
              , PackageName "raaz-random"
              , PackageName "raaz-ssh"
              ]

-- | Travis Environment given by HASKELL_PLATFORM and PARALLEL_BUILDS
-- environment variables set alongwith their corresponding constraints.
data TravisEnv = TravisEnv { haskellPlatform    :: Maybe String
                           , parallelBuilds     :: Bool
                           , installConstraints :: [Dependency]
                           , verboseConstraints :: [String]
                           } deriving (Eq, Show)

-- | The main routine which gets all the parsed results from cabal files of
-- packages and then resolve dependencies to get a linear list of packages
-- which is then installed.
main :: IO ()
main = do allgpds <- getAllGPD allPackages
          args <- getArgs
          case args of
            [cmd]     -> do exitCode <- buildPackages cmd
                                        . resolveDependency
                                        . getPackageDepency
                                            allPackages $ allgpds
                            case exitCode of
                              ExitSuccess -> exitSuccess
                              otherwise   -> exitFailure
            otherwise -> error "Invalid argument provided."

-- | To build all packages linearly.
buildPackages :: String -> [PackageName] -> IO ExitCode
buildPackages cmd []     = return ExitSuccess
buildPackages cmd (x:xs) = do exitCode <- makePackage cmd x
                              case exitCode of
                                ExitSuccess -> buildPackages cmd xs
                                otherwise   -> exitFailure

-- | Build a single package with a command line argument.
makePackage :: String -> PackageName -> IO ExitCode
makePackage cmd package =
  do setCurrentDirectory $ "./" ++ getPackageName package
     exitCode <- case cmd of
       "install" -> do putStrLn $ "Installing of **"
                                  ++ getPackageName package
                                  ++ "** package started."
                       setCurrentDirectory "../"
                       constraints <- getPlatformConstraints
                       buildOpts   <- getParallelBuildOpts
                       setCurrentDirectory $ "./" ++ getPackageName package
                       let installArgs = filter (not . null) $
                                           [ "install"
                                           , buildOpts
                                           , "--only-dependencies"
                                           , "--enable-documentation"]
                                           ++ constraints
                       exitDepend  <- makeCommand
                                        package
                                        ExitSuccess
                                        "cabal"
                                        installArgs
                                        "Installing Dependencies of"
                       exitInstall <- makeCommand
                                        package
                                        exitDepend
                                        "cabal"
                                        ["install"]
                                        "Installing"
                       return exitInstall
       "config"  -> do putStrLn $ "Configuring of **"
                                  ++ getPackageName package
                                  ++ "** package started."
                       exitConfigure <- makeCommand
                                          package
                                          ExitSuccess
                                          "cabal"
                                          [ "configure"
                                          , "--enable-tests"]
                                          "Configuring"
                       return exitConfigure
       "build"   -> do putStrLn $ "Building of **"
                                  ++ getPackageName package
                                  ++ "** package started."
                       exitBuild <- makeCommand
                                      package
                                      ExitSuccess
                                      "cabal"
                                      ["build"]
                                      "Building"
                       return exitBuild
       "test"    -> do putStrLn $ "Testing of **"
                                  ++ getPackageName package
                                  ++ "** package started."
                       exitTests <- makeCommand
                                      package
                                      ExitSuccess
                                      "cabal"
                                      [ "test"
                                      , "--show-details=failures"]
                                      "Testing"
                       return exitTests
       "tarball" -> makeCommand
                      package
                      ExitSuccess
                      "cabal"
                      ["sdist"]
                      "Creating Source tarball of"
       otherwise -> error "Invalid argument provided."
     setCurrentDirectory "../"
     return exitCode

-- | Run commands for different steps of building.
makeCommand :: PackageName
            -> ExitCode
            -> String
            -> [String]
            -> String
            -> IO ExitCode
makeCommand package prevCode command args msg =
              if prevCode == ExitSuccess
                then do exitCode <- rawSystem command args
                        if exitCode == ExitSuccess
                            then do putStrLn $ msg ++ " **"
                                                   ++ getPackageName package
                                                   ++ "** package done."
                                    return ExitSuccess
                            else do error $ msg ++ " failed for **"
                                                ++ getPackageName package
                                                ++ "** package."
                                    exitFailure
                else return prevCode

-- | Get the flags if parallel build environment variable is set.
getParallelBuildOpts :: IO String
getParallelBuildOpts =
  do env <- getEnvironment
     case (lookup "PARALLEL_BUILDS" env) of
       Just "yes" -> return "-j"
       Nothing    -> return ""

-- | Get the constraints if platform environment variable is set.
getPlatformConstraints :: IO [String]
getPlatformConstraints =
  do env <- getEnvironment
     case (lookup "HASKELL_PLATFORM" env) of
       Just platform -> do desc <- readPackageDescription silent $
                                     "./platform/cabal/" ++ platform ++ ".cabal"
                           return . map mapFn
                                  . getDependencies $ desc
       Nothing       -> return []
  where mapFn (Dependency pn vr) = "--constraint="
                                     ++ (show $ disp pn)
                                     ++ (show $ disp vr)

-- | Get all the non-raaz dependencies from all packages.
getNonRaazDependencies :: Packages
                       -> [GenericPackageDescription]
                       -> [PackageName]
getNonRaazDependencies packages gpds = Set.toList . Set.fromList
                                                  . concat $ map mapFn gpds
  where mapFn gpd = filter filterFn $ getDepencyList gpd
          where filterFn x = not $ x `elem` (getPackages packages)

-- | Results of parsing cabal file of all packages.
getAllGPD :: Packages -> IO [GenericPackageDescription]
getAllGPD = foldl foldFn (return []) . reverse . getPackages
  where foldFn iogpds package = do gpds <- iogpds
                                   desc <- readPackageDescription silent $
                                             "./" ++ getPackageName package
                                                   ++ "/"
                                                   ++ getPackageName package
                                                   ++ ".cabal"
                                   return $ desc:gpds

-- | Get package name.
getPackageName :: PackageName -> String
getPackageName (PackageName str) = str

-- | Take the map and provide a linear list of dependency-free packages.
resolveDependency :: Map.Map PackageName [PackageName] -> [PackageName]
resolveDependency map
  | Map.null map  =  []
  | otherwise     =  resolvedPackages ++ resolveDependency finalUnresolvedMap
  where (resolvedMap, unresolvedMap) = Map.partition null map
        resolvedPackages = Map.keys resolvedMap
        finalUnresolvedMap = Map.map (\\ resolvedPackages) unresolvedMap

-- | Genrate a map of package and its dependencies, excluding those which
-- does not belong to raaz packages.
getPackageDepency :: Packages
                  -> [GenericPackageDescription]
                  -> Map.Map PackageName [PackageName]
getPackageDepency packages gpds = foldl foldFn Map.empty zipped
  where zipped = zipWith fzip gpds $ getPackages packages
          where fzip gpd package = ( package
                                   , filter filterFn $ getDepencyList gpd)
                  where filterFn x = x `elem` (getPackages packages)
                                     && x /= package
        foldFn map (package, dependency) = Map.insert package dependency map

-- | Get package names of the dependencies
getDepencyList :: GenericPackageDescription -> [PackageName]
getDepencyList = map getPackageName . getDependencies
  where getPackageName (Dependency name _) = name

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
