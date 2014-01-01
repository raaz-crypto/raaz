import Data.Version

import Paths_raaz_random(version)
import Test.Framework (defaultMain, testGroup)
import qualified Modules.Stream as Stream

pkgName = "raaz-random-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Raaz.Random.Stream" Stream.tests ]
