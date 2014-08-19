-- | This scripts parses cabal files of different raaz packages and
-- installs all the packages in linear fashion by resolving
-- dependencies programmatically.

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
import           System.FilePath
import           System.Directory
import           System.Process

-------------------- Configuration ------------------------

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


-- | Relative path to the platform cabal file
platformCabal :: String -> FilePath
platformCabal p = "platform" </> "cabal" </> p <.> "cabal"

-- | Relative path to the package cabal file
packageCabal  :: String -> FilePath
packageCabal pkg = pkg </> pkg <.> "cabal"


---------------------------------------------------------------------

-- | Travis Environment given by HASKELL_PLATFORM and PARALLEL_BUILDS
-- environment variables set alongwith their corresponding
-- constraints.
data TravisEnv = TravisEnv { haskellPlatform    :: Maybe String
                           , parallelBuilds     :: Bool
                           , installConstraints :: [Dependency]
                           , verboseConstraints :: [String]
                           } deriving (Eq, Show)

-- | The main routine which gets all the parsed results from cabal
-- files of packages and then resolve dependencies to get a linear
-- list of packages which is then installed.
main :: IO ()
main = do allgpds   <- getAllGPD allPackages
          travisEnv <- getTravisEnv
          args      <- getArgs
          case args of
            [cmd]     -> mapM_ (makePackage travisEnv cmd)
                               (resolve allgpds)
            otherwise -> error "Invalid argument provided."
  where resolve = resolveDependency . getPackageDepency allPackages

-- | Build a single package with a command line argument.
makePackage :: TravisEnv -> String -> PackageName -> IO ()
makePackage travisEnv cmd package =
  do setCurrentDirectory $ "./" ++ getPackageName package
     exitCode <- case cmd of
       "install" -> sequence_
                    [ cabalCmd
                        ([ "install"
                         , "--only-dependencies"
                         ] ++ verboseConstraints travisEnv)
                        "Installing Dependencies of"
                    , cabalCmd
                        [ "install"
                        , "--enable-documentation"
                        ]
                        "Installing"
                    ]
       "config"  -> cabalCmd ["configure", "--enable-tests"] "Configuring"
       "build"   -> cabalCmd ["build"] "Building"
       "test"    -> cabalCmd ["test", "--show-details=failures"] "Testing"
       "tarball" -> cabalCmd ["sdist"] "Creating Source tarball of"
       otherwise -> error "Invalid argument provided."
     setCurrentDirectory "../"
     return exitCode
  where cabalCmd = makeCommand package "cabal"

-- | To execute commands with arguments on packages.
makeCommand :: PackageName -> String -> [String] -> String -> IO ()
makeCommand package command args msg =
  do putStrLn startMsg
     exitCode <- rawSystem command args
     case exitCode of ExitSuccess -> putStrLn doneMsg
                      otherwise   -> error failMsg
  where startMsg = msg ++ " **" ++ getPackageName package ++ "** started."
        doneMsg  = msg ++ " **" ++ getPackageName package ++ " ** done."
        failMsg  = msg ++ " failed for **" ++ getPackageName package ++ "** ."

-- | Results of parsing cabal file of all packages.
getAllGPD :: [PackageName] -> IO [GenericPackageDescription]
getAllGPD = mapM mapFn
  where mapFn pkg = parseCabal $ packageCabal $ getPackageName pkg

---------------------- Helper functions ------------------------------

-- | Get Travis Environment.
getTravisEnv :: IO TravisEnv
getTravisEnv =
  do env <- getEnvironment
     hp  <- return . lookup "HASKELL_PLATFORM" $ env
     pb  <- return . lookup "PARALLEL_BUILDS" $ env
     ct  <- maybe (return []) getConstraint hp
     return TravisEnv { haskellPlatform    = hp
                      , parallelBuilds     = paraBuild pb
                      , installConstraints = ct
                      , verboseConstraints = getVerbose ct $ paraBuild pb
                      }
  where paraBuild     = maybe False (=="yes")
        getConstraint pf = fmap getDependencies
                         $ parseCabal $ platformCabal pf
        getVerbose ct pb = map constraint ct ++ ["-j" | pb]
        constraint (Dependency pn vr) = "--constraint="
                                      ++ show (disp pn)
                                      ++ show (disp vr)

-- | To parse a cabal file
parseCabal :: FilePath -> IO GenericPackageDescription
parseCabal = readPackageDescription silent

-- | Get all the non-raaz dependencies from all packages.
getNonRaazDependencies :: [PackageName]
                       -> [GenericPackageDescription]
                       -> [PackageName]
getNonRaazDependencies packages = concatMap mapFn
  where mapFn     = filter filterFn . getDepencyList
        filterFn  = flip notElem packages

-- | Get package name.
getPackageName :: PackageName -> String
getPackageName = show . disp

-- | Take the map and provide a linear list of dependency-free packages.
resolveDependency :: Map.Map PackageName [PackageName] -> [PackageName]
resolveDependency map
  | Map.null map  =  []
  | otherwise     =  resolvedPackages ++ resolveDependency finalUnresolvedMap
  where (resolvedMap, unresolvedMap) = Map.partition null map
        resolvedPackages   = Map.keys resolvedMap
        finalUnresolvedMap = Map.map (\\ resolvedPackages) unresolvedMap

-- | Genrate a map of package and its dependencies, excluding those which
-- does not belong to raaz packages.
getPackageDepency :: [PackageName]
                  -> [GenericPackageDescription]
                  -> Map.Map PackageName [PackageName]
getPackageDepency packages gpds = foldl foldFn Map.empty zipped
  where zipped = zipWith fzip gpds packages
          where fzip gpd package = ( package
                                   , filter filterFn $ getDepencyList gpd)
                  where filterFn x = x `elem` packages && x /= package
        foldFn map (package, dependency) = Map.insert package dependency map

-- | Get package names of the dependencies.
getDepencyList :: GenericPackageDescription -> [PackageName]
getDepencyList = map mapFn . getDependencies
  where mapFn (Dependency name _) = name

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
