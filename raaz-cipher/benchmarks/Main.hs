import           Data.Version
import           Criterion.Main        (defaultMainWith)
import           Criterion             (bgroup)
import           Criterion.Config      (Config(..), ljust, defaultConfig)
import           Paths_raaz_cipher     (version)

import qualified Modules.ECB           as ECB
import qualified Modules.CBC           as CBC
import qualified Modules.CTR           as CTR


pkgName = "raaz-cipher-" ++ showVersion version

myConfig :: Config
myConfig = defaultConfig {
  cfgSamples = ljust 10
  }

main :: IO ()
main = do putStrLn $ "Running benchmarks for " ++ pkgName
          defaultMainWith myConfig (return ()) benchmarksTiny

benchmarksTiny = [ bgroup "Raaz.Cipher.AES.ECB" ECB.benchmarksTiny ]

benchmarks = [ bgroup "Raaz.Cipher.AES.ECB" ECB.benchmarks
             , bgroup "Raaz.Cipher.AES.CBC" CBC.benchmarks
             , bgroup "Raaz.Cipher.AES.CTR" CTR.benchmarks
             ]
