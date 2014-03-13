-- The Haskell script that builds a local repo with all the raaz
-- packages in it. Cabal install then uses this local repo together
-- with hackage to get its work done. Used mainly to install the raaz
-- packages directly from the git repository. It is also used by the
-- travis build system.

import Control.Applicative
import Distribution.Package
import Distribution.PackageDescription
import Distribution.PackageDescription.Parse
import Distribution.Verbosity                ( silent )
import Distribution.Text
import System.Directory
import System.Environment
import System.FilePath

---------------------- Local repo format     -------------------------
--
-- The Repository format consists of the following.
--
-- 1. An 00-index.tar.gz file that contains the cabal files of all the
-- packages supported by the repo. If the repo distributes the package foo
-- with version 1.0.1 then there will be a file foo/1.0.1/foo.cabal inside
-- the 00-index.tar.gz
--
-- 2. The source tar ball. The source tar ball foo-1.0.1.tar.gz is also
-- available. It should be located at /foo/1.0.1/foo-1.0.1.tar.gz
--

-- | The root of the local repository
repoRoot :: FilePath
repoRoot = "local-repo"

-- | The path to the index file.
indexTGZ :: FilePath
indexTGZ = repoRoot </> "00-index" <.> "tar" <.> "gz"

-- | The root of the given package in the repository
repoPackageDir :: PackageIdentifier -> FilePath
repoPackageDir pkgID = repoRoot </> show n </> show v
  where v = disp $ pkgVersion pkgID
        n = disp $ pkgName pkgID

-- | The path of the cabal file in the repository.
repoPackageCabal :: PackageIdentifier -> FilePath
repoPackageCabal pkgID = repoPackageDir pkgID </> n <.> "cabal"
  where n   = show $ disp $ pkgName pkgID

-- | The package tarball
repoPackageTGZ :: PackageIdentifier -> FilePath
repoPackageTGZ pkgID = repoPackageDir pkgID </> show pkg <.> "tar" <.> "gz"
  where pkg = disp pkgID

-- | The path to the package tarball.
packageTGZ :: FilePath -> PackageIdentifier -> FilePath
packageTGZ fp pkgID = fp </> "dist" </> show pkg <.> "tar" <.> "gz"
  where pkg = disp pkgID

packageCabal :: FilePath -> PackageIdentifier -> FilePath
packageCabal fp pkgID = fp </> n <.> "cabal"
  where n = show $ disp $ pkgName pkgID


---------------------- Reading a raaz package ------------------------

-- | Read the raaz package given the file path where it resides
readPackageID :: FilePath -> IO PackageIdentifier
readPackageID pkgDir = packId <$> readPackageDescription silent cabal
  where pName  = takeFileName pkgDir
        cabal  = pkgDir </> pName <.> "cabal"
        packId = package . packageDescription

---------------------- The Main routine ------------------------------

createRepo :: [FilePath] -> IO ()
createRepo = mapM_ go
  where go fp = do
          pid <- readPackageID fp

          -- Create the package root
          mkdir $ repoPackageDir pid
          -- Copy the cabal file
          cp (packageCabal fp pid) $ repoPackageCabal pid
          -- Copy the source tar ball
          cp (packageTGZ   fp pid) $ repoPackageTGZ   pid

mkdir :: FilePath -> IO ()
mkdir dir = do
  putStrLn $ "raaz-repo: creating " ++ dir
  createDirectoryIfMissing True dir

cp :: FilePath -> FilePath -> IO ()
cp src dest = do
  putStrLn $ "raaz-repo:" ++ src ++ " -> " ++ dest
  copyFile src dest

main :: IO ()
main = getArgs >>= createRepo
