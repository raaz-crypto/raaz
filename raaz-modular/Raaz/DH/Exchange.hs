{- |

Diffie - Hellman Key Exchange.

-}

module Raaz.DH.Exchange where


import Raaz.Core.Primitives.Cipher

import Raaz.DH.Types
import Raaz.Random
import Raaz.Number


-- | Generates the private number x (1 < x < q) and public number e = g^x mod p.
generateParams :: ( StreamGadget g
                  , Modular w
                  , Integral w
                  )
               => RandomSource g
               -> Group w
               -> IO (PrivateNum w,PublicNum w)
generateParams rsrc (Group p g q) = do
  x <- genBetween rsrc 2 (q - 1)
  return (PrivateNum x, PublicNum $ powModulo g x p)

-- | Calculate the shared secret.
calculateSecret :: Modular w
                => Group w
                -> PrivateNum w
                -> PublicNum w
                -> SharedSecret w
calculateSecret grp (PrivateNum y) (PublicNum e) =
  SharedSecret $ powModulo e y $ prime grp
