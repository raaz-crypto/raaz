#!/usr/bin/env runhaskell

> import Data.Default
> import Distribution.PackageDescription
> import Distribution.Simple.LocalBuildInfo
> import Distribution.Simple.Setup
> import Distribution.Simple
> import System.Directory
> import System.FilePath
> import System.Info

> import Config
> import Config.Linux


> -- | The directory where the header files are put.
> systemDir    = "includes/raaz/system"
> 
> -- | The actual header file
> systemHeader = systemDir </> "parameters.h"
>
> -- | The ifdef symbol used to protect the header file.
> systemHeaderSymbol = "__RAAZ_SYSTEM_PARAMETERS_H__"


> main = defaultMainWithHooks simpleUserHooks { confHook = raazConfigure }


The actual configuration. Essentially write the system parameters on
the the header file and run the default user hooks.

> raazConfigure :: (GenericPackageDescription, HookedBuildInfo)
>               -> ConfigFlags
>               -> IO LocalBuildInfo
> raazConfigure gpd flags = do systemParameterConfigure
>                              confHook simpleUserHooks gpd flags
> 


This write the system dependent header file.

> systemParameterConfigure :: IO ()
> systemParameterConfigure = do
>   putStrLn "configure:"
>          
>   "creating the directory " ++ systemDir  ++ "/"
>      <:> createDirectoryIfMissing True systemDir
>          
>   configStr <- fmap toString config
>          
>   "writing to " ++ systemHeader
>      <:> writeFile systemHeader $ protectWith systemHeaderSymbol configStr
>         

Compute the system parameters based on which platform we are in.

> config :: IO Parameters
> config | os == "linux" = Config.Linux.configure
>        | otherwise     = do inform $ "platform is generic (" ++ os ++ ")"
>                             return def
