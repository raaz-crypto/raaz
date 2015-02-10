module Raaz.Core.Random
  ( Random(..)
  , RandomDev(..)
  , openPseudoRandom
  , openEntropy
  ) where

import System.IO (openBinaryFile, Handle, IOMode(..))

newtype RandomDev = RandomDev Handle

openPseudoRandom :: IO RandomDev
openPseudoRandom = do
  handle <- openBinaryFile "/dev/urandom" ReadMode
  return $ RandomDev handle

openEntropy :: IO RandomDev
openEntropy = do
  handle <- openBinaryFile "/dev/random" ReadMode
  return $ RandomDev handle

class Random a where
  gen :: RandomDev -> IO a
