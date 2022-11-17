{-# LANGUAGE TypeFamilies                #-}
module Raaz.Core.KeyExchange
       ( -- * Key exchange.
         -- $terminology$
         Private
       , Exchange
       , Secret
       ) where

import Raaz.Core.Prelude

-- $terminology$
--
-- Consider a key exchange between two peers Alice and Bob. There are three
-- important data that is used in the protocol.
--
-- [Private Key:] Each peer generates a key that is know to only
--    themselves.  This could be a static key (i.e might be used
--    multiple times) or a ephemeral key (key per session).
--
-- [Exchange data:] The peer who holds the secret key `K` can generates the
--    corresponding exchange data `Eₖ` that is to be set to the peer at the
--    other end of the communication. The exchange data can be sent through a
--    public channel and an adversary will not be able to get hold of `K` from
--    merely knowing `Eₖ`.
--
-- [Shared Secret:] Consider two peers Alice and Bob with the
--    respective private keys `Ka` and `Kb`. Let `Ea` and `Eb` be the
--    respective exchange data, then Alice and Bob can establish a
--    shared `Sab` at their individual by knowing ones private key and
--    the other peers public key, i.e. Alice generates `Sab` from Ka
--    (which is known to her) and Eb (which is sent to her by Bob) over
--    the insecure channel. Similarly, Bob can generated `Sab` from
--    knowing `Kb` and `Ea`. However, an adversary cannot generate `Sab`
--    from merely knowing `Ea` and `Eb` which is the public communication
--    between Alice and Bob.
--
-- We have separate types for each of these data types.
--


-- | The key private to a party that iassociated with the exchange
-- algorithm.
data family Private       kx  :: Type

-- | The data that is to be exchanged between the peers for the
-- establishment of the shared secret.
data family Exchange      kx  :: Type

-- | The shared secret that is established between the peer at each
-- end of the communication once each of the peer receives the
-- exchange communication from the other end.
data family Secret  kx  :: Type
