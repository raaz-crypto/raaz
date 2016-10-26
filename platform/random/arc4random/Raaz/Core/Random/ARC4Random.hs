{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE CPP                        #-}
-- | This module exposes a system wide prng which uses the arc4random
-- library call that is available on most bsds and also on linux using
-- the @<bsd/stdlib.h>@
module Raaz.Core.Random.ARC4Random
       ( ARC4RandomPRG, newARC4RandomPRG
       ) where

import Raaz.Core.Types
import Raaz.Core.Random.PRG

-- | The psrg that uses the arc4random_buf call to get its randomness. This is
-- an attractive source of randomness because of the following
-- reasons.
--
-- 1. It seeds from the system wide entropy pool.

-- 2. It avoids opening /dev/urandom which can be problematic due to
--    exhaustion of file descriptors and other issues.

-- 3. It gives the best of breed randomness that can be meaningfully
-- supported on the given platform.
--
-- ARC4 concern: The `arc4random` call /does not/ use ARC4 cipher
-- anymore (it uses chacha20 internally). The prefix `arc4` in
-- `arc4random` should be read as "A replacement call for" instead of
-- "Alleged RC4". It might be good to really check this on your
-- platform before making it the system prg on you system.
data ARC4RandomPRG = ARC4RandomPRG deriving Show

foreign import ccall unsafe "arc4random_buf" c_arc4random_buf
    :: Pointer -> BYTES Int -> IO ()

instance PRG ARC4RandomPRG where
  fillRandomBytes bytes ptr _ = c_arc4random_buf ptr bytes


-- | Getting a new instance of ARC4RandomPRG.
newARC4RandomPRG :: IO ARC4RandomPRG

# ifdef NO_ARC4RANDOM_STIR

newARC4RandomRandomPRG = return ARC4RandomPRG

# else
-- | We might require stirring
foreign import ccall unsafe "arc4random_stir" c_arc4random_stir
    :: IO ()

newARC4RandomPRG = do c_arc4random_stir
                      return ARC4RandomPRG

#endif
