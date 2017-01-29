module Raaz.RandomSpec where

import Common
import Raaz.Random

spec :: Spec
spec = it "system prg should return different words on distinct calls"
       $ compareWords `shouldReturn` False
  where r64                 :: RandM Word64
        r64                 = random
        compareWords        = insecurely $ (==) <$> r64 <*> r64
