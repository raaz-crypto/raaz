#!/usr/bin/env runhaskell

> import Distribution.PackageDescription
> import Distribution.Simple.LocalBuildInfo
> import Distribution.Simple.Setup
> import Distribution.Simple
> import System.Directory
> import System.FilePath
> import Config


> root     = "includes" </> "raaz" </> "primitives" -- ^ package root
> autoConf = root </> "autoconf.h"                  -- ^ auto-detected stuff

> main :: IO ()
> main = defaultMainWithHooks simpleUserHooks { confHook = raazConfigure }

The actual configuration. Essentially write the system parameters on
the the header file and run the default user hooks.

> raazConfigure :: (GenericPackageDescription, HookedBuildInfo)
>               -> ConfigFlags
>               -> IO LocalBuildInfo
> raazConfigure gpd flags = do putStr $ "creating directory: " ++ root ++ "..."
>                              createDirectoryIfMissing True root
>                              putStrLn "done."
>
>                              putStrLn $ "writing " ++ autoConf ++ "..."
>                              genConfigFile autoConf configure
>                              putStrLn $ "done writing " ++ autoConf ++ "."
>
>                              confHook simpleUserHooks gpd flags
>
