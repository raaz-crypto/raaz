module Digest.Sha512Spec where

import           Digest
import qualified Digest.Sha512.CPortable    as CP
import qualified Digest.Sha512.CHandWritten as CH

spec :: Spec
spec = digestSpec [ (CP.name, CP.digest)
                  , (CH.name, CH.digest)
                  ]
