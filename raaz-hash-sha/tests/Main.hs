import Data.Version
import Paths_raaz_hash_sha(version)

pkgName = "raaz-hash-sha-" ++ showVersion version

main :: IO ()
main = do putStrLn $ "Running tests for " ++ pkgName
