import Config
import System.Directory
import System.FilePath

systemDir    = "includes/raaz/system"
systemHeader = systemDir </> "parameters.h"

preamble = unlines [ "/* Generated with the configure script do not modify */"
                   , "# ifndef __RAAZ_SYSTEM_PARAMETERS_H__"
                   , "# define __RAAZ_SYSTEM_PARAMETERS_H__"
                   , ""
                   ]
endif   = "# endif"

main :: IO ()
main = do putStrLn "configure:"
          
          "creating the directory " ++ systemDir  ++ "/"
            <:> createDirectoryIfMissing True systemDir
          
          configStr <- config
          
          "writing to " ++ systemHeader
            <:> writeFile systemHeader $ preamble ++ configStr ++ endif
         
config = return ""
