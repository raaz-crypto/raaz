import qualified Data.ByteString             as BS
import           Data.Version

import qualified Modules.Number              as Number
import qualified Modules.Stream              as Stream
import           Paths_raaz_random           (version)
import           Test.Framework              (defaultMain, testGroup)

import           Raaz.Core.Primitives
import           Raaz.Core.Primitives.Cipher
import           Raaz.Core.Util.ByteString   (fromByteString)

import           Raaz.Cipher.AES.CTR
import           Raaz.Cipher.AES.Internal

pkgName = "raaz-random-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
          defaultMain tests

tests = [ testGroup "Raaz.Random.Stream" (Stream.testWith g k)
        , testGroup "Raaz.Random.Number" (Number.testWith g k)
        ]
  where
    g :: CAESGadget CTR KEY128 EncryptMode
    g = undefined
    k = (fromByteString $ BS.replicate 128 1, fromByteString $ BS.replicate 128 1)
