import Data.Version

import Paths_src(version)
import qualified Cipher as Cipher
import qualified Core as Core
import qualified Curves as Curves
import qualified Hash as Hash
import qualified Modular as Modular
import qualified Random as Random
import Test.Framework (defaultMain, testGroup)

pkgName = "raaz-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Cipher" Cipher.tests
        , testGroup "Core" Core.tests
        , testGroup "Curves" Curves.tests
        , testGroup "Hash" Hash.tests
        , testGroup "Modular" Modular.tests
        , testGroup "Random" Random.tests
        ]
