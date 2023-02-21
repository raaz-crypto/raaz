{-# LANGUAGE TypeFamilies                #-}
module Raaz.Core.KeyExchange
       ( -- * Key exchange.
         -- $terminology$
         KeyExchange(..)
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
-- [Exchange data:] The peer who holds the secret key `K` generates
--    the corresponding exchange data `Eₖ` that is sent to the peer at
--    the other end of the communication. The exchange data need not
--    be a secret as typically it is exchanged via public channel. The
--    mere knowledge of `Eₖ` will not give any information of the
--    secret key `K` the adversary.
--
-- [Shared Secret:] Consider two peers Alice and Bob with the
--    respective private keys `Ka` and `Kb`. Let `Ea` and `Eb` be the
--    respective exchange data, then both Alice and Bob can establish
--    a shared `Sab` among themselves at their individual ends by
--    knowing only their own private key and exchange data of the
--    peer, i.e. Alice generates `Sab` from Ka (which is known
--    to her) and Eb (which is sent to her by Bob) over the insecure
--    channel. Similarly, Bob can generated `Sab` from knowing `Kb`
--    and `Ea`. However, an adversary cannot generate `Sab` from
--    merely knowing `Ea` and `Eb` which is the public communication
--    between Alice and Bob.
--
-- We have separate types for each of these data types.
--

class KeyExchange kx where

  -- | The key private key associated with the exchange algorithm.
  data Private kx  :: Type

  -- | The data that is to be exchanged between the peers for the
  -- establishment of the shared secret.
  data Exchange  kx  :: Type

  -- | The shared secret that is established between the peer at each
  -- end of the communication once each of the peer receives the
  -- exchange communication from the other end.
  data Secret  kx  :: Type
