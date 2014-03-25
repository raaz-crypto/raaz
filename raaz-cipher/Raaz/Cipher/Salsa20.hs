{- |

Salsa20 is a stream cipher submitted to eSTREAM. Internally, the
cipher uses XOR, 32-bit addition, and constant-distance rotation
operations on an internal state of 16 32-bit words. This choice of
operations avoids the possibility of timing attacks in software
implementations.

Salsa20 with all the three variants of 20 rounds, 12 rounds and 8
rounds are implemented here.

-}
module Raaz.Cipher.Salsa20
       ( Salsa20
       , KEY128
       , KEY256
       , R20, R12, R8
       , Nonce
       , Counter
       , module Raaz.Primitives
       , module Raaz.Primitives.Cipher
       ) where

import Raaz.Primitives
import Raaz.Primitives.Cipher

import Raaz.Cipher.Salsa20.Instances
import Raaz.Cipher.Salsa20.Internal
