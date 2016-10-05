module Raaz.Core.SystemPRGSpec where

import Common

spec :: Spec
spec = it "system prg should return different words on distinct calls"
       $ compareWords `shouldReturn` False
  where randomWord :: SystemPRG -> IO Word
        randomWord  = getRandom
        compareWords = do systemPRG <- newSystemPRG
                          (==) <$> randomWord systemPRG
                               <*> randomWord systemPRG
