module Raaz.RandomSpec where

import Tests.Core
import Raaz.Random

spec :: Spec
spec = it "system prg should return different words on distinct calls"
       $ compareWords `shouldReturn` False
  where r64                 :: RandomState -> IO Word64
        r64                 = random
        compareWords        = withRandomState $ \ state -> (==) <$> r64 state  <*> r64 state
