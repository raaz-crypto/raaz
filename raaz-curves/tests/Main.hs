import           Data.Version

import           Paths_raaz_curves (version)
import qualified Modules.EC25519.Defaults as EC25519
import           Test.Framework     (defaultMain, testGroup)

pkgName = "raaz-curves-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "EC25519" EC25519.tests ]
