import           Data.Version
import           Criterion.Main    (defaultMainWith)
import           Criterion         (bgroup)
import           Criterion.Config  (Config(..), ljust, defaultConfig)
import           Paths_raaz_curves (version)
import           System.Random

import           Raaz.Curves.EC25519
import           Raaz.Curves.EC25519.Internal

import qualified EC25519.Defaults as EC

pkgName = "raaz-curves-" ++ showVersion version

main :: IO ()
main = do
  gen <- newStdGen
  let (r1,gen1) = randomR (1, curve25519P - 1) gen
      (r2,gen2) = randomR (1, curve25519P - 1) gen1
  putStrLn $ "Running benchmarks for " ++ pkgName
  defaultMainWith defaultConfig (return ()) $ benchmarks (integerToP25519 r1, integerToP25519 r2)

benchmarks (r1,r2) = [ bgroup "Secret & PublicToken Generation" $ EC.benchSecretPublic
                     , bgroup "Secret & PublicToken Generation with random provided" $ EC.benchParamsGivenRandom r1
                     , bgroup "Shared Secret Generation with random provided" $ EC.benchSharedSecret (r1,r2)
                     ]
