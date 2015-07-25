import Data.Version

import Paths_src(version)
import qualified Hash.Sha1 as Sha1
import qualified Hash.Sha224 as Sha224
import qualified Hash.Sha256 as Sha256
import qualified Hash.Sha384 as Sha384
import qualified Hash.Sha512 as Sha512
import qualified Hash.Blake256 as Blake256
import Test.Framework (defaultMain, testGroup)


pkgName = "raaz-hash" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Raaz.Hash.Sha:Sha1" Sha1.tests
        , testGroup "Raaz.Hash.Sha:Sha224" Sha224.tests
        , testGroup "Raaz.Hash.Sha:Sha256" Sha256.tests
        , testGroup "Raaz.Hash.Sha:Sha384" Sha384.tests
        , testGroup "Raaz.Hash.Sha:Sha512" Sha512.tests
        , testGroup "Raaz.Hash.Blake:Blake256" Blake256.tests
        ]
