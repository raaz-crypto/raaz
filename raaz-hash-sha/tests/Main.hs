import Data.Version

import Paths_raaz_hash_sha(version)
import qualified Modules.Sha1 as Sha1
import Test.Framework (defaultMain, testGroup)


pkgName = "raaz-hash-sha-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Raaz.Hash.Sha:Sha1" Sha1.tests
        ]
