-- |
-- Module      : Raaz.AuthEncrypt
-- Description : Authenticated encryption
-- Copyright   : (c) Piyush P Kurur, 2016
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
module Raaz.AuthEncrypt ( -- * Authenticated encryption
                          --
                          -- $locking$
                          lock, unlock
                          -- ** Locking with additional data
                          -- $aead$
                        , lockWith, unlockWith
                        , AEAD, Locked, Cipher, Key
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
-- xoring it with the keystream @KS@ generated using the key @K@, from
-- Bob's point of view it is impossible to know whether it was some
-- nonsense that Eve sent or whether it was from Alice who wanted to
-- actually send the message @R ⊕ KS@. In many situations, Eve can
-- exploit this ability to fake communication and breach the security
-- of the protocol. Authenticated encryption is to solve this issue.
--
-- == Authenticated encryption via message locking
--
-- To send a message @m@ using a key @k@, Alice computes the locked
-- variant using the function `lock`. At Bobs end, he can unlock this
-- locked message using the function `unlock`. If there has been any
-- tampering of message on the way from A to B, the unlocking will
-- fail. It is computationally infeasible to decrypt or fake the
-- authentication without knowing the key. Sometimes the protocol
-- requires additional authenticated data. The `lockWith` and the
-- `unlockWith` variants are used for this purpose.
--
-- == Key reuse.
--
-- Authenticated encryption needs, not just a key, but also a
-- nounce. Under the hood, both `lock` and `lockWith` uses randomly
-- generated nounce for each invocation (hence the result is an @IO@
-- type). This ensures that the key-nounce pair is never reused. It is
-- therefore safe to lock multiple messages with the same key.

-- $aead$
--
-- Some protocols have additional data that needs to be factored in
-- when sending the locked packet. In such situations one can use the
-- `lockWith` and `unlockWith` variants.


-- $security$
--
-- __WARNING:__ The security of the interface is compromised if
--
-- 1. The key gets revealed to the attacker or
--
-- 2. In the case of the unsafe versions (`unsafeLock` and
--    `unsafeLockWith`) which uses explicit nounce, if the same
--    key/nounce pair is used to lock two different messages.
--
-- Nounces need not be private and may be exposed to the attacker. In
-- fact we pack the nounce into the AEAD structure.

-- $specific$
--
-- The library exposes the following two authenticated encryption algorithm
--
-- * Raaz.AuthEncrypt.ChaCha20Poly1305
-- * Raaz.AuthEncrypt.XChaCha20Poly1305
--
-- of which the latter (XChaCha20Poly1305) is used by default. Both of
-- these modules only provide the unsafe version. In the case of the
-- former (ChaCha20Poly1305), the nounce is a bit too small (96-bits)
-- and random generation has a nontrivial chance of collison. It is
-- however, slightly faster and is safe to use when there is frequent
-- key resets as in the case of network protocols. As with other cases
-- we recommend the use of the default interface instead of the
-- specific one when ever possible.



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
