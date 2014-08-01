import           Data.Version

import           Paths_raaz_curves (version)
import           Test.Framework     (defaultMain, testGroup)

pkgName = "raaz-curves-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = []
