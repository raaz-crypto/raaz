import           Data.Version

import           Paths_raaz_random      (version)
import           Test.Framework         (defaultMain, testGroup)
import qualified Modules.Stream         as Stream
import qualified Modules.Number         as Number

import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Cipher.AES.CTR
import           Raaz.Cipher.AES.Internal

pkgName = "raaz-random-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Raaz.Random.Stream" (Stream.testWith g)
        , testGroup "Raaz.Random.Number" (Number.testWith g)
        ]
  where
    g :: CGadget (AESOp CTR KEY128 EncryptMode)
    g = undefined
