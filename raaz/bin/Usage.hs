module Usage( usage, errorBailout ) where

import Prelude
import System.Console.GetOpt
import System.IO
import System.Exit

-- | The usage message for the program.
usage :: [OptDescr a]  -- ^ options
      -> String        -- ^ Header
      -> [String]      -- ^ errors
      -> String
usage options header errs
  | null errs = usageInfo header options
  | otherwise = "raaz: " ++ unlines errs ++ usageInfo header options



-- | Bail out on error
errorBailout :: [OptDescr a] -- ^ Options
             -> String       -- ^ Header
             -> [String]     -- ^ Errors
             -> IO b
errorBailout opts str errs = do
  hPutStrLn stderr $ usage opts str errs
  exitFailure
