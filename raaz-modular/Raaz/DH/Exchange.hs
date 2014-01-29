{- |

Diffie - Hellman Key Exchange.

-}

module Raaz.DH.Exchange where


import Raaz.Primitives.Cipher
import Raaz.Random

import Raaz.DH.Types
import Raaz.Number.Generate
import Raaz.Number.Util


-- | Generates the private number x (1 < x < q) and public number e = g^x mod p.
generateParams :: StreamGadget g
               => RandomSource g
               -> Group
               -> IO (PrivateNum,PublicNum)
generateParams rsrc (Group p g q) = do
  x <- genBetween rsrc 2 (q - 1)
  return (PrivateNum x, PublicNum $ powModulo g x p)

-- | Calculate the shared secret.
calculateSecret :: Group -> PrivateNum -> PublicNum -> SharedSecret
calculateSecret grp (PrivateNum x) (PublicNum e) =
  SharedSecret $ powModulo e x $ prime grp
