
module Config
       ( configure
       , genConfigFile
       ) where

import System.FilePath

import Raaz.Config.Monad
import Raaz.Config.FFI
import Config.Cache(cache)
import Config.Page(pageSize)

-- | The main configuration action. This justs packages the actual
-- configuration.
configure = do
  comment "Auto generated stuff (do not edit)"
  wrapHeaderFile "__RAAZ_PRIMITIVES_AUTOCONF_H__" actualConfig

-- | Here is where the actual configuration happens.
actualConfig :: ConfigM ()
actualConfig = do
  section "Cache parameters" configureCache
  section "Page Size parameters" configurePageSize
  section "Endian functions" checkEndian
  section "Memory locking"   checkMemoryLocking
  section "Aligned Memory Allocation"   checkMemAlign

section :: String -> ConfigM () -> ConfigM ()
section com action = do comment com
                        action
                        comment $ "End of " ++ com
                        newline

-- | Configuring the L1 and L2 cache values.
configureCache = do (l1,l2) <- cache
                    define "RAAZ_L1_CACHE" $ show l1
                    define "RAAZ_L2_CACHE" $ show l2

-- | Configuring Page Size.
configurePageSize = do
  p <- pageSize
  define "RAAZ_PAGE_SIZE" $ show p

-- | Checking for endian conversion functions.
checkEndian = do haveFFIFunction "htole32"
                 haveFFIFunction "htole64"
                 haveFFIFunction "htobe32"
                 haveFFIFunction "htobe64"

-- | Check memory locking
checkMemoryLocking = do
  haveFFIFunction "mlock"
  haveFFIFunction "mlockall"

-- | Check memory locking
checkMemAlign = haveFFIFunction "memalign"

haveFFIFunction :: String -> ConfigM ()
haveFFIFunction funcName = do chk <- ffiTest ffiPath
                              if chk then define' $ "RAAZ_HAVE_" ++ funcName
                                 else undef $ "RAAZ_HAVE_" ++ funcName
   where ffiPath = "Config" </> "ffi" </> funcName
