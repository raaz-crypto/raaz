import           Data.Version
import           Criterion.Main    (defaultMainWith)
import           Criterion         (bgroup)
import           Criterion.Config  (Config(..), ljust, defaultConfig)
import           Paths_raaz_hash   (version)

import qualified Modules.Sha       as Sha
import qualified Modules.Blake     as Blake

import           Modules.Defaults

pkgName = "raaz-hash-" ++ showVersion version

myConfig :: Config
myConfig = defaultConfig {
  cfgSamples = ljust 10
  }

main :: IO ()
main = do putStrLn $ "Running benchmarks for " ++ pkgName
          putStrLn $ "Data Size : " ++ show nSize
          b <- benchmarks
          defaultMainWith myConfig (return ()) b

benchmarks = do
  sha <- Sha.benchmarks
  blake <- Blake.benchmarks
  return [ bgroup "SHA" sha 
         , bgroup "BLAKE" blake
         ]
