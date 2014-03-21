{-|

Code to run some ffiTest

-}

module Config.FFI
       ( ffiTest
       ) where

import System.Cmd
import System.Exit
import System.FilePath

import Config.Monad

-- | Converts exit status to
status :: ExitCode -> IO Bool
status  ExitSuccess       = do putStrLn "SUCCESS"; return True
status (ExitFailure code) = do putStrLn $ "FAILED (status code: "
                                 ++ show code
                                 ++ ")"
                               return False

-- | The `ffiTest testDir`, compiles and runs the test located under
-- the directory testDir. Use this to test out whether a C function is
-- exposed in your platform and whether it works as exptected.
--
-- The directory structure of a test directory is as follows:
--
-- testDir: The directory where the source is located
--
-- testDir/test.c: The C functions required for the test
--
-- testDir/Test.hs: The Haskell code that makes use of the C functions
--   in test.c/ For more reliable code you may include quickcheck
--   tests as well
--
-- testDir/DESCRIPTION: One line description of what is being tested.
--
-- testDir/README: Optional readme for more clarification (mainly for
--   developers).
--
ffiTest :: FilePath -> ConfigM Bool
ffiTest = doIO . ffiTestIO

-- | The actual IO action.
ffiTestIO :: FilePath -- ^ test directory
          -> IO Bool
ffiTestIO fp = do
  printDescr
  cstat <- compile
  if cstat then run else return False
  where c     = fp </> "test.c"
        hs    = fp </> "Test.hs"
        test  = fp </> "test"
        ghc   = rawSystem "ghc" [ "-v0", c, hs, "-o", test]
        compile    = do putStr "compile:"
                        ghc >>= status
        run        = rawSystem test [] >>= status
        printDescr = do readFile (fp </> "DESCRIPTION") >>= putStr
                        putStr "..."
