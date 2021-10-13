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
                        , Locked, Cipher

                          -- ** Meta information
                        , authEncryptAlgorithm

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
-- == Safety against key reuse
--
-- The interface exposed here is safe /even with key reuse/. Under the
-- hood, both `lock` and `lockWith` uses randomly generated nounce for
-- each invocation (hence the result is an @IO@ type). The nounce is
-- large (192-bits) and is generated using cryptographically secure
-- pseudo-random generator (csprg). Thus even when a particular key is
-- used multiple times, each such invocation is paired with a distinct
-- nounce thereby preventing the reuse of the (key, nounce)-pair.
--
-- == Serialisation
--
-- Unfortunately, there does not seem to be an agreed upon format for
-- serialising AEAD tokens. As a result the Locked type does not have
-- an instance of `Encodable` unlike the message digest and message
-- authentication type. However, for particular wire protocol, one can
-- take apart the AEAD token using the "Raaz.AuthEncrypt.Unsafe"
-- interface and individually serialise the constituents.
--
-- == Security assumption
--
-- The security of the interface is compromised if and only if the key
-- gets exposed. Otherwise an adversary should not be able to read,
-- tamper or forge Locked data.
--

-- $aead$
--
-- Some protocols have additional data that needs to be factored in
-- when sending the locked packet. In such situations one can use the
-- `lockWith` and `unlockWith` variants.
