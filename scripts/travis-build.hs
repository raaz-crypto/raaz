-- | This scripts parses cabal file of packages and installs all the packages
-- in linear fashion by resolving dependencies programmatically.


import           Control.Applicative
import           Data.List
import qualified Data.Map                              as Map  
import           Data.Maybe
import           Distribution.Package
import           Distribution.PackageDescription
import           Distribution.PackageDescription.Parse
import           Distribution.Verbosity
import           System.Exit
import           System.Directory
import           System.Process

-- | All the packages to be installed
allPackages :: Packages
allPackages = Packages [ PackageName "raaz"
                       , PackageName "raaz-random"
                       , PackageName "raaz-cipher"
                       , PackageName "raaz-hash"
                       , PackageName "raaz-ssh"
                       , PackageName "raaz-benchmarks"
                       , PackageName "raaz-core"
                       , PackageName "raaz-modular"
                       ]

newtype Packages = Packages { getPackages :: [PackageName] } deriving Show

-- | The main routine which gets all the parsed results from cabal files of
-- packages and then resolve dependencies to get a linear list of packages
-- which is then installed.
main :: IO ()
main = do allgpds <- getAllGPD allPackages
          exitCode <- buildPackages . resolveDependency 
                                    . getPackageDepency allPackages $ allgpds
          case exitCode of ExitSuccess -> do putStrLn "All is well."
                                             exitSuccess
                           otherwise   -> do putStrLn "Build failed."
                                             exitFailure

-- | To build all packages linearly
buildPackages :: [PackageName] -> IO ExitCode
buildPackages []     = return ExitSuccess
buildPackages (x:xs) = do exitCode <- makePackage x
                          if exitCode == ExitSuccess
                            then buildPackages xs
                            else do error $ "Building failed for **"
                                             ++ getPackageName x
                                             ++ "** package."
                                    exitFailure

-- | Build a single package
makePackage :: PackageName -> IO ExitCode
makePackage package = 
  do putStrLn $ "Making of **" 
                 ++ getPackageName package
                 ++ "** package started."
     setCurrentDirectory $ "./" ++ getPackageName package
     exitDepend    <- makeCommand package ExitSuccess
                                  "cabal install --only-dependencies"
                                  "Installing Dependencies"
     exitConfigure <- makeCommand package exitDepend 
                                  "cabal configure --enable-tests" "Configuring"
     exitBuild     <- makeCommand package exitConfigure "cabal build" "Building"
     exitTests     <- runTestsOfPackage package exitBuild
     exitInstall   <- makeCommand package exitTests "cabal install" "Installing"
     setCurrentDirectory "../"
     return exitInstall

-- | Run commands for different steps of building
makeCommand :: PackageName -> ExitCode -> String -> String -> IO ExitCode
makeCommand package prevCode command msg =
              if prevCode == ExitSuccess
                then do exitCode <- system command
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

-- | Run tests from executable
runTestsOfPackage :: PackageName -> ExitCode -> IO ExitCode
runTestsOfPackage package prevCode =
          if prevCode == ExitSuccess
            then do isFile <- doesFileExist "./dist/build/tests/tests"
                    if isFile
                      then do exitCode <- system "./dist/build/tests/tests"
                              if exitCode == ExitSuccess
                                 then do putStrLn $ "Testing **" 
                                                     ++ getPackageName package
                                                     ++ "** package done."
                                         return ExitSuccess
                                 else do error $ "Testing failed for **"
                                                  ++ getPackageName package
                                                  ++ "** package."
                                         exitFailure
                      else return prevCode
            else return prevCode

-- | Results of parsing cabal file of all packages
getAllGPD :: Packages -> IO [GenericPackageDescription]
getAllGPD = foldl foldFn (return []) . reverse . getPackages
  where foldFn iogpds package = do gpds <- iogpds
                                   desc <- readPackageDescription silent $
                                             "./" ++ getPackageName package
                                                   ++ "/"
                                                   ++ getPackageName package
                                                   ++ ".cabal"
                                   return $ desc:gpds

-- | Get package name
getPackageName :: PackageName -> String
getPackageName (PackageName str) = str

-- | Take the map and provide a linear list of dependency-free packages
resolveDependency :: Map.Map PackageName [PackageName] -> [PackageName]
resolveDependency map
  | Map.null map  =  []
  | otherwise     =  resolvedPackages ++ resolveDependency finalUnresolvedMap
  where (resolvedMap, unresolvedMap) = Map.partition null map
        resolvedPackages = Map.keys resolvedMap
        finalUnresolvedMap = Map.map (\\ resolvedPackages) unresolvedMap

-- | Genrate a map of package and its dependencies, excluding those which
-- does not belong to raaz packages
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
