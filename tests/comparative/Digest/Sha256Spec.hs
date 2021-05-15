module Digest.Sha256Spec where

import           Digest
import qualified Digest.Sha256.CPortable    as CP
import qualified Digest.Sha256.CHandWritten as CH

spec :: Spec
spec = digestSpec[ (CP.name, CP.digest)
                 , (CH.name, CH.digest)
                 ]
