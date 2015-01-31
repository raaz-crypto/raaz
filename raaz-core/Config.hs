{-|

This module does the configuration. It has logic to detect various
parameters. Nevertheless it also allows for manual configurations of
each and every parameters. For the manual options you can edit the top
section of this module.


-}
module Config
       ( configure
       , genConfigFile
       ) where

import Control.Monad
import Data.Maybe (fromMaybe)
import System.FilePath

import Config.Monad
import Config.FFI
import Config.Cache
import Config.Page(pageSize)


------------------ Defaults ---------------------------------------
--
-- These are the options that we use as defaults when autoconf is not
-- being used. If you want manual configurations edit this and
-- configure with --no-autoconf
--

-- | Size of the L1 cache.
l1CacheSize :: Int
l1CacheSize = 32768

-- | Size of the L2 cache.
l2CacheSize :: Int
l2CacheSize = 32768

-- | Size of a virtual memory page.
defaultPageSize :: Int
defaultPageSize = 4096

-- | Functions that the C environment provides. Uncomments the ones
-- that are required. Currently all functions are disabled but you can
-- include in this list a subset of what is available in
-- functionsToCheck
availableFunctions :: [String]
availableFunctions =  []


-- | Functions whose existance is checked by the auto configuration.
functionsToCheck = [ "htole32"
                   , "htole64"
                   , "htobe32"
                   , "htobe64"
                   , "be32toh"
                   , "be64toh"
                   , "le32toh"
                   , "mlock"
                   , "mlockall"
                   , "memalign"
                   ]



-- | The main configuration action. This justs packages the actual
-- configuration.
configure :: Bool -> ConfigM ()
configure auto = do
  comment "Auto generated stuff (do not edit)"
  wrapHeaderFile "__RAAZ_PRIMITIVES_CONF_H__" $ actualConfig auto

-- | Here is where the actual configuration happens.
actualConfig :: Bool -> ConfigM ()
actualConfig auto = do
  comment
    (if auto then "System parameters guessed by Config.hs"
             else "System parameters set by manual configuration")

  section "Cache parameters"     $ configureCache auto
  section "Page Size parameters" $ configurePageSize auto

  section "Mark all FFI functions unavailable" $
    forM_ functionsToCheck dontHave

  section "Selectively enable the available ones." $
    if auto then forM_ functionsToCheck checkFFIFunction
      else forM_ availableFunctions have

section :: String -> ConfigM () -> ConfigM ()
section com action = do comment com
                        action
                        comment $ "End of " ++ com
                        newline

-- | Configuring the L1 and L2 cache values.
configureCache auto
  | auto = do
    maybel1 <- getL1CacheSize
    maybel2 <- getL2CacheSize
    let l1 = fromMaybe l1CacheSize maybel1
        l2 = fromMaybe l2CacheSize maybel2
      in do cacheMesg "L1" maybel1 l1
            cacheMesg "L2" maybel2 l2
            define "RAAZ_L1_CACHE" $ show l1
            define "RAAZ_L2_CACHE" $ show l2
  | otherwise = do
    messageLn $ "\tSetting default cache sizes: L1 = "
      ++ show l1CacheSize ++ " L2 = " ++ show l2CacheSize
    define "RAAZ_L1_CACHE" $ show l1CacheSize
    define "RAAZ_L2_CACHE" $ show l2CacheSize

  where cacheMesg cType guess actual = messageLn $ unwords [
          "\tGuessed", cType, "=", show guess,
          "setting it to", show actual
          ]



-- | Configuring Page Size.
configurePageSize auto = do
  p <- if auto then pageSize else return defaultPageSize
  define "RAAZ_PAGE_SIZE" $ show p


checkFFIFunction :: String -> ConfigM ()
checkFFIFunction funcName = do
  chk <- ffiTest ffiPath
  when chk $ have funcName
  where ffiPath = "Config" </> "ffi" </> funcName


have :: String -> ConfigM ()
have func = define' $ "RAAZ_HAVE_" ++ func

dontHave :: String -> ConfigM ()
dontHave func = undef $ "RAAZ_HAVE_" ++ func
