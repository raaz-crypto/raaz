{-|

Diffie - Hellman Key exchange

-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Raaz.DH
       (
       -- * Oakley Groups
         oakley1
       , oakley2
       , oakley5
       , oakley14
       , oakley15
       , oakley16
       , oakley17
       , oakley18
       -- * DH Types
       , SharedSecret
       , PublicNum
       , PrivateNum
       -- * DH exchange
       , generateParams
       , calculateSecret
       , module Raaz.KeyExchange
       ) where

import Raaz.Number
import Raaz.DH.Exchange
import Raaz.DH.Types

import Raaz.KeyExchange

instance KeyExchange DHOakley1 Word1024 where
  generate _ r = generateParams r oakley1
  getSecret _ = calculateSecret oakley1

instance KeyExchange DHOakley14 Word2048 where
  generate _ r = generateParams r oakley14
  getSecret _ = calculateSecret oakley14
