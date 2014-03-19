import           Data.Version
import           Criterion.Main        (defaultMainWith)
import           Criterion             (bgroup)
import           Criterion.Config      (Config(..), ljust, defaultConfig)
import           Paths_raaz_cipher     (version)

import qualified Modules.AES           as AES

pkgName = "raaz-cipher-" ++ showVersion version

myConfig :: Config
myConfig = defaultConfig {
  cfgSamples = ljust 10
  }

main :: IO ()
main = do putStrLn $ "Running benchmarks for " ++ pkgName
          defaultMainWith myConfig (return ()) benchmarksTiny

benchmarksTiny = [ bgroup "AES" AES.benchmarksTiny ]

benchmarks = [ bgroup "AES" AES.benchmarks ]
