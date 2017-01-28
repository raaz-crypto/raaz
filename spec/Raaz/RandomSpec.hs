module Raaz.RandomSpec where

import Common
import Raaz.Random

spec :: Spec
spec = it "system prg should return different words on distinct calls"
       $ compareWords `shouldReturn` False
  where randomWord :: RandM Word64
        randomWord  = random
        compareWords = (==) <$> insecurely randomWord
                            <*> insecurely randomWord
