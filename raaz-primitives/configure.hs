import          Config
import qualified Config.Linux

import Data.Default
import System.Directory
import System.FilePath
import System.Info

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
         
config | os == "linux" = fmap toString Config.Linux.configure
       | otherwise     = do inform $ "platform is generic (" ++ os ++ ")"
                            return $ toString def
