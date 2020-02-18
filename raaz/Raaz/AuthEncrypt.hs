-- | Authenticated encryption.
module Raaz.AuthEncrypt ( -- ** Message locking
                          --
                          -- $locking$
                          lock, unlock
                          -- ** Locking with additional data
                          -- $aead$
                        , lockWith, unlockWith
                        , AEAD, Locked

                        -- ** Security Assumption
                        -- $security$

                        -- ** Specific Authenticated encryptions
                        -- $specific$
                        ) where

import Raaz.V1.AuthEncrypt

-- $locking$
--
-- Suppose that Alice wants to send a private message to Bob that
-- should not be seen by anyone else. Alice can use their shared
-- secret key @K@ to encrypt the message, which Bob decrypts when he
-- receives it. The secrecy of the key @K@ ensures that a third party
-- Eve will not be able to read what Alice sends. However, it is
-- possible for Eve to forge message and pretend that it has
-- originated from Alice. Consider a string @R@ that Bob receives
-- purportedly from Alice. Since stream ciphers encrypt message @M@ by
-- xoring it with the keystream @cipher K@, from Bob's point of view
-- it is impossible to know whether it was some nonsense that Eve sent
-- or whether it was from Alice who wanted to actually send the
-- message @R ⊕ cipher K@. In many situations, Eve can indeed exploit
-- this and break the communication between Alice and
-- Bob. Authenticated encryption is to solve this issue.
--
-- To send a message @m@ using a key @k@ and a nounce @n@, Alice
-- computes the locked variant @lmesg = `lock` k n m@. At Bobs end, he
-- can unlock it using the function @`unlock` k n lmesg@. It is
-- computationally infeasible for a third party that does not know @K@
-- to produce @`lock` k n x@ for any @x@. Thus for a message @x@ if
-- @`unlock` k n x@ succeeds, then Bob is not only guaranteed of its
-- secrecy but also the fact that the message indeed originated from
-- Alice.


-- $aead$
--
-- Some protocols have additional data that needs to be factored in
-- when sending the locked packet. In such situations one can use the
-- `lockWith` and `unlockWith` variants.


-- $security$
--
-- __WARNING:__ The security of the @lock/unlock@ or its AEAD variants @lockWith/unlockWith@ is
-- /compromised/ if one of the following happens
--
-- 1. The key gets revealed to the attacker.
--
-- 2. The same key/nounce pair is used to lock two different messages.
--
-- For nounces, only uniqueness is required and may be exposed to the
-- attacker. If a single key is shared for multiple messages, Alice
-- and Bob needs to have a strategy to pick the nounces which ensure
-- that a fresh nounce is picked for each message. Some common
-- strategy is to maintain a sequence number (we really do not care
-- about the predictability of the nounce) but with the choice of
-- primitives that we make here, one can just pick nounce at random
-- for each message, thereby making the communication protocol
-- completely stateless.


-- $specific$
--
-- The library exposes the following two authenticated encryption algorithm
--
-- * Raaz.AuthEncrypt.ChaCha20Poly1305
-- * Raaz.AuthEncrypt.XChaCha20Poly1305
--
-- In the case of the former, one needs to be careful with the nounce
-- as it is small (96-bits). There is a chance that randomly picked
-- nounces can collide and compromise the security. It is however,
-- slightly faster and is safe to use when there is frequent key
-- resets as in the case of network protocols.
