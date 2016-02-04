module Raaz.Core.SystemPRGSpec where

import Control.Applicative
import Data.Word
import Test.Hspec

import Raaz.Core.Random

spec :: Spec
spec = do it "system prg should return two different words for two distinct calls" $ do
            compareWords `shouldReturn` False
  where randomWord :: SystemPRG -> IO Word
        randomWord  = random
        compareWords = do systemPRG <- newPRG ()
                          (==) <$> randomWord systemPRG
                               <*> randomWord systemPRG
