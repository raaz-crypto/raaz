-- | Authenticated encryption.
module Raaz.AuthEncrypt ( -- ** Message locking
                          --
                          -- $locking$
                          lock, unlock
                          -- ** Locking with additional data
                          -- $aead$
                        , lockWith, unlockWith

                        -- ** Security Assumption
                        -- $security$

                        -- ** Specific Authenticated encryptions
                        -- $specific$

                        -- ** Constructing and Taking apart.
                        -- $takingapart$

                        , AEAD, Locked
                        , unsafeAEAD, unsafeToCipherText, unsafeToAuthTag
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
-- message @R ⊕ cipher K@. In many situations, Eve can exploit this
-- ability to fake communication and breach the security of the
-- protocol. Authenticated encryption is to solve this issue.
--
-- To send a message @m@ using a key @k@ and a nounce @n@, Alice
-- computes the locked variant @lmesg = `lock` k n m@ of the
-- message. At Bobs end, he can unlock this locked message using the
-- function @`unlock` k n lmesg@. If there has been any tampering of
-- message on the way from A to B, the unlocking will fail. It is
-- computationally infeasible to decrypt or fake the authentication
-- without knowing the key.
--

-- $aead$
--
-- Some protocols have additional data that needs to be factored in
-- when sending the locked packet. In such situations one can use the
-- `lockWith` and `unlockWith` variants.


-- $security$
--
-- __WARNING:__ The security of the @lock/unlock@ or its AEAD variants
-- @lockWith/unlockWith@ is /compromised/ if one of the following
-- happens
--
-- 1. The key gets revealed to the attacker.
--
-- 2. The same key/nounce pair is used to lock two different messages.
--
-- Nounces need not be private and may be exposed to the
-- attacker. However, if a single key is shared for locking multiple
-- messages, Alice and Bob should have a strategy to pick unique
-- nounces for each message. For example one can use a sequence number
-- to pick nounces. However such a strategy would require the two
-- peers to maintain a state (the sequence number). The nounce in our
-- case is large and hence if we pick nounces at random for each
-- message, the chances of collision is negligible. This makes the
-- communication protocol completely stateless.

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


-- $takingapart$
--
-- Values belonging to the `Locked` and `AEAD` types are meant to be
-- used as opaque objects. While unlocking these types, we do not
-- decrypt untill the tag is verified. This helps in quickly rejecting
-- fake packets without wasting time on decryption and improves the
-- security against DoS attacks. Taking apart the cipher text and the
-- authentication token can lead to incorrect handling and hence is
-- __not__ recommended in general. Nonetheless, when implementing
-- protocols that use AEAD, we might want to build and take apart
-- these types. We give now give functions for these unsafe operations
-- on AEAD packets.
