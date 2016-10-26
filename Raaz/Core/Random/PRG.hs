-- | The pseudo random generator class.
module Raaz.Core.Random.PRG
       ( PRG(..), Seedable(..), fillRandom
       ) where

import Raaz.Core.Types

-- | The class that captures pseudo-random generators. Essentially the
-- a pseudo-random generator (PRG) is a byte sources that can be
-- seeded. It is expected that the `fillRandomBytes` call should fill
-- in high quality random bytes in to the Pointer.
class PRG prg where

  fillRandomBytes :: BYTES Int -> Pointer -> prg -> IO ()


-- | The class captures prgs that can be seeded.
class Seedable prg where

  -- | Seed a given prg from a valid source prg.
  seedFrom :: PRG srcPrg => srcPrg -> prg -> IO ()

-- | Generalised version of fillRandomBytes that takes an arbitrary length
-- unit.
fillRandom :: (PRG prg, LengthUnit l)
           => l
           -> Pointer
           -> prg
           -> IO ()
fillRandom = fillRandomBytes . inBytes
