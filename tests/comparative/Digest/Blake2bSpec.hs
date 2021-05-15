module Digest.Blake2bSpec where

import           Digest
import qualified Digest.Blake2b.CPortable    as CP
import qualified Digest.Blake2b.CHandWritten as CH

spec :: Spec
spec = digestSpec  [ (CP.name, CP.digest)
                   , (CH.name, CH.digest)
                   ]
