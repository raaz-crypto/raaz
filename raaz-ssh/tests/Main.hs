import           Data.Version
import           Paths_raaz_ssh (version)

pkgName = "raaz-ssh-" ++ showVersion version

main :: IO ()
main = putStrLn $ "Running tests for " ++ pkgName
