{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE CPP                        #-}
-- | This module exposes a system wide prng which uses the arc4random
-- library call that is available on most bsds and also on linux using
-- the @<bsd/stdlib.h>@
module Raaz.Core.Random.SystemPRG
       ( SystemPRG, newSystemPRG
       ) where

import Raaz.Core.Types
import Raaz.Core.Random.PRG

-- | The psrg that uses the arc4random_buf call to get its randomness. This is is
-- an attractive source of randomness because of the following reasons.
--
-- 1. It seeds from the system wide entropy pool.
-- 2. It avoids opening /dev/urandom which can be problematic due to
--    exhaustion of file descriptors and other issues.
-- 3. It gives the best of breed randomness that can be meaningfully supported on
--    the given platform.
--
-- ARC4 concern: The `arc4random` call /does not/ use ARC4 cipher
-- anymore (it uses chacha20 internally). The prefix `arc4` in
-- `arc4random` should be read as "A replacement call for" instead of
-- "Alleged RC4". It might be good to really check this on your
-- platform before making it the system prg on you system.
data SystemPRG = ARC4RandomPRG deriving Show

foreign import ccall unsafe "arc4random_buf" c_arc4random_buf
    :: Pointer -> BYTES Int -> IO ()

instance PRG SystemPRG where
  fillRandomBytes bytes ptr _ = c_arc4random_buf ptr bytes


-- | Getting a new instance of ARC4RandomPRG.
newSystemPRG :: IO SystemPRG

# ifdef NO_ARC4RANDOM_STIR

newSystemRandomPRG = return ARC4RandomPRG

# else
-- | We might require stirring
foreign import ccall unsafe "arc4random_stir" c_arc4random_stir
    :: IO ()

newSystemPRG = do c_arc4random_stir
                  return ARC4RandomPRG

#endif
