{-# LANGUAGE CPP               #-}
-- | The system wide prg.
module Raaz.Core.Random.System
       ( SystemPRG, newSystemPRG
       ) where
#if SYSTEMPRG_CRYPTO_GEN_RANDOM
-- Windows systems.

type SystemPRG = ()

newSystemPRG :: IO SystemPRG
newSystemPRG = fail "not implemented"

#else
-- Posix systems.

#if SYSTEMPRG_ARC4RANDOM

import Raaz.Core.Random.ARC4Random

-- | The system wide pseudo random generator.
type SystemPRG = ARC4RandomPRG

-- | Gets a new systemwide pseudo random generator.
newSystemPRG :: IO SystemPRG
newSystemPRG = newARC4RandomPRG

#else

import Raaz.Core.Random.DevUrandom

-- | The system wide pseudo random generator.
type SystemPRG = DevUrandomPRG

-- | Gets a new systemwide pseudo random generator.
newSystemPRG :: IO SystemPRG
newSystemPRG = newDevUrandomPRG


-- end posix systems
#endif

-- end SYSTEM_CRYPTO_GEN_RANDOM
#endif
