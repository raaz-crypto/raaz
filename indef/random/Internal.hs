-- | Some internal functions exposed by raaz mainly for testing
-- purposes. The functions here are pretty low level and/or expose to
-- much of the system details. If you find your self needing some of
-- the functions here, it should be treated as a bug in raaz. Please
-- file an issue.
module Internal
      ( fillSystemEntropy, entropySource, csPRG
      ) where

import Implementation ( name )
import Raaz.Core
import Entropy

-- | __WARNING__ Never use this function directly. Only exposed for
-- testing the quality of system entropy. Fill the given input buffer
-- with from the system entropy pool. This is provided only to test
-- the quality of the system entropy function with systems like
-- die-harder. The function is going to be less safe (due to the low
-- level nature of the function) and slower (due to system call
-- overheads).
fillSystemEntropy :: LengthUnit l => l -> Pointer -> IO (BYTES Int)
fillSystemEntropy = getEntropy . inBytes

csPRG :: String
csPRG = name
