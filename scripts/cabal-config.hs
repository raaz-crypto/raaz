-- This script generates the cabal config file required for building
-- the raaz packages.  It takes two arguments namely the path to the
-- local repository and an optional path to the cabal file
-- corresponding to a haskell platform and generates the cabal config
-- file that
--
-- 1. Sets an additional local-repo for the raaz packages.
-- 2. If the second argument is given, then parses that cabal file and
--    adds all the dependencies there as constraints.
--
-- This script is used by the travis system for raaz to build platform
-- specific versions.
--
import Control.Applicative
import Data.List
import Data.Maybe
import Distribution.Package
import Distribution.PackageDescription
import Distribution.PackageDescription.Parse
import Distribution.Text
import Distribution.Verbosity
import System.Environment
import System.FilePath
import System.IO
import Text.PrettyPrint

---------------- Manipulating dependencies ------------------------

-- | Get the dependencies in a particular cabal file.
getDependencies :: FilePath -> IO [Dependency]
getDependencies fp = do
  gdescr <- readPackageDescription silent fp
  let -- The dependencies.
      libDeps   = condTreeToDependency <$> condLibrary gdescr
      exeDeps   = sectionDeps           $ condExecutables gdescr
      testDeps  = sectionDeps           $ condTestSuites gdescr
      bmarkDeps = sectionDeps           $ condBenchmarks gdescr
      allDeps   = exeDeps `union` testDeps `union` bmarkDeps `union`
                  fromMaybe [] libDeps
      -- helpers
      condTreeToDependency (CondNode _ deps _) = deps
      sectionDeps = foldl union [] . map  (condTreeToDependency . snd)
    in return allDeps

-- | Generate the cabal constraint line that fixes the dependency. This
-- is used to make platform specific builds for travis.
cabalConstraint :: Dependency -> Doc
cabalConstraint ds = text "constraint:" <+> disp ds

------------------ The main program ---------------------------------
cabalConfig  :: FilePath -> Maybe FilePath -> IO ()
cabalConfig lp platform = do
  deps <- maybe (return []) getDependencies platform
  let localRepoConfig = text "local-repo:" <+> text lp
      constraints     = vcat $ map cabalConstraint deps
      config          = localRepoConfig $$ constraints
    in print config

main :: IO ()
main = do args <- getArgs
          case args of
            [r, l]    -> cabalConfig (r </> l) Nothing
            [r, l, p] -> cabalConfig (r </> l) (Just p)
            _         -> usage

usage :: IO ()
usage =  hPutStrLn stderr "usage: cabal-config root local-repo-path [platform]"
