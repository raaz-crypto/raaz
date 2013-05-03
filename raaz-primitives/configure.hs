import Config
import Data.Default
import System.Directory
import System.FilePath

systemDir    = "includes/raaz/system"
systemHeader = systemDir </> "parameters.h"
systemHeaderSymbol = "__RAAZ_SYSTEM_PARAMETERS_H__"

main :: IO ()
main = do putStrLn "configure:"
          
          "creating the directory " ++ systemDir  ++ "/"
            <:> createDirectoryIfMissing True systemDir
          
          configStr <- config
          
          "writing to " ++ systemHeader
            <:> writeFile systemHeader $ protectWith systemHeaderSymbol configStr
         
config = return $ toString def
