import           Data.Version
import           Criterion.Main    (defaultMainWith)
import           Criterion         (bgroup)
import           Criterion.Config  (Config(..), ljust, defaultConfig)
import           Paths_raaz_cipher (version)

import qualified Modules.AES       as AES
import qualified Modules.Salsa20   as S20

import           Modules.Defaults

pkgName = "raaz-cipher-" ++ showVersion version

myConfig :: Config
myConfig = defaultConfig {
  cfgSamples = ljust 10
  }

main :: IO ()
main = do putStrLn $ "Running benchmarks for " ++ pkgName
          putStrLn $ "Data Size : " ++ show nSize
          defaultMainWith myConfig (return ()) benchmarksTiny

benchmarksTiny = [ bgroup "AES" AES.benchmarksTiny
                 , bgroup "Salsa20" S20.benchmarksTiny
                 ]

benchmarks = [ bgroup "AES" AES.benchmarks
             , bgroup "Salsa20" S20.benchmarks
             ]
