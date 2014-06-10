import           Data.Bits
import           Data.Version
import           Criterion.Main    (defaultMainWith)
import           Criterion         (bgroup)
import           Criterion.Config  (Config(..), ljust, defaultConfig)
import           Paths_raaz_modular (version)
import           System.Random

import qualified Modules.Number.Modular as Modular

pkgName = "raaz-modular-" ++ showVersion version

main :: IO ()
main = do
   gen <- newStdGen
   let glist  = (take 100) $ randomRs (2, 200) gen
       klist  = (take 100) $ randomRs (1 `shiftL` 500, 1 `shiftL` 1000) gen
       mlist  = (take 100) $ randomRs (1 `shiftL` 500, 1 `shiftL` 1000) gen
       glist' = (take 100) $ randomRs (2, 200) gen
       klist'  = (take 100) $ randomRs (1 `shiftL` 500, 1 `shiftL` 501 - 1) gen
       mlist'  = (take 100) $ randomRs (1 `shiftL` 500, 1 `shiftL` 501 - 1) gen
   putStrLn $ "Running benchmarks for " ++ pkgName
   defaultMainWith defaultConfig (return ()) $ benchmarks (Modular.ParamList glist klist mlist glist' klist' mlist')

benchmarks p = [ bgroup "Modular Exponentiation" $ Modular.benchExponentiation p ]
