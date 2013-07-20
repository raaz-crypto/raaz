
module Config
       ( configure
       , genConfigFile
       ) where

import System.FilePath

import Config.Monad
import Config.FFI
import Config.Cache(cache)


-- | The main configuration action. This justs packages the actual
-- configuration.
configure = do
  section "Auto generated stuff (do not edit)" $
    wrapHeaderFile "__RAAZ_PRIMITIVES_AUTOCONF_H__" actualConfig

-- | Here is where the actual configuration happens.
actualConfig :: ConfigM ()
actualConfig = do
  section "Cache parameters" configureCache
  section "Endian functions" checkEndian

section :: String -> ConfigM () -> ConfigM ()
section com action = do comment com
                        action
                        comment $ "End of " ++ com
                        newline

-- | Configuring the L1 and L2 cache values.
configureCache = do (l1,l2) <- cache
                    define "RAAZ_L1_CACHE" $ show l1
                    define "RAAZ_L2_CACHE" $ show l2

-- | Checking for endian conversion functions.
checkEndian = do haveFFIFunction "htole32"
                 haveFFIFunction "htole64"
                 haveFFIFunction "htobe32"
                 haveFFIFunction "htobe64"

haveFFIFunction :: String -> ConfigM ()
haveFFIFunction funcName = do chk <- ffiTest ffiPath
                              if chk then define' $ "RAAZ_HAVE_" ++ funcName
                                 else undef $ "RAAZ_HAVE_" ++ funcName
   where ffiPath = "Config" </> "ffi" </> funcName
