import Data.Version

import Paths_raaz_hash_sha(version)
import qualified Modules.Sha1 as Sha1
import qualified Modules.Sha224 as Sha224
import qualified Modules.Sha256 as Sha256
import Test.Framework (defaultMain, testGroup)


pkgName = "raaz-hash-sha-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Raaz.Hash.Sha:Sha1" Sha1.tests
        , testGroup "Raaz.Hash.Sha:Sha224" Sha224.tests
        , testGroup "Raaz.Hash.Sha:Sha256" Sha256.tests
        ]
