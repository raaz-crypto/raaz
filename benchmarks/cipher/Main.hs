import           Data.Version
import           Criterion.Main    (defaultMainWith)
import           Criterion         (bgroup)
import           Criterion.Config  (Config(..), ljust, defaultConfig)
import           Paths_src         (version)

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
          b <- benchmarksTiny
          defaultMainWith myConfig (return ()) b

benchmarksTiny = do
  aes <- AES.benchmarksTiny
  salsa <- S20.benchmarksTiny
  return [bgroup "AES" aes, bgroup "Salsa20" salsa]

benchmarks= do
  aes <- AES.benchmarks
  salsa <- S20.benchmarks
  return [bgroup "AES" aes, bgroup "Salsa20" salsa]
