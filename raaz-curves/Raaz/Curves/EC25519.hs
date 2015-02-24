{-|

The DJB's curve EC25519.
Montgomery curve equation : by^2 = x^3 + ax^2 + x, p = prime, g = basepoint
for EC25519: A = 486662, C = A/4, prime p = 2^255 - 19, basepoint Gx = 9

-}

module Raaz.Curves.EC25519
       ( P25519
       , Secret25519
       , PublicToken25519
       , SharedSecret25519
       , generateSecretEC25519
       , publicToken
       , sharedSecret
       , getRandomForSecret
       , params25519Reco
       , sharedSecret25519Reco
       ) where

import Raaz.Curves.EC25519.Internal
import Raaz.Curves.EC25519.CPortable
