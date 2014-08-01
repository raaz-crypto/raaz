import           Data.Bits
import           Data.Version
import           Criterion.Main    (defaultMainWith)
import           Criterion         (bgroup)
import           Criterion.Config  (Config(..), ljust, defaultConfig)
import           Paths_raaz_curves (version)

pkgName = "raaz-curves-" ++ showVersion version

main :: IO ()
main = do
   putStrLn $ "Running benchmarks for " ++ pkgName
   defaultMainWith defaultConfig (return ()) benchmarks

benchmarks = []
