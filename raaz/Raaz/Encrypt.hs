-- | Message encryption in Raaz. Consider using "Raaz.AuthEncrypt"
-- instead of this module as it also prevents message faking by a
-- third party.
module Raaz.Encrypt ( -- ** Message encryption
                      --
                      -- $message-encryption$
                      Cipher
                    , encrypt, decrypt
                    , encryptAt, decryptAt

                      -- *** Specific message encryption
                      -- $specific-encryption$
                    ) where

import           Raaz.V1.Encrypt

-- $message-encryption$
--
-- This module exposes a way to encrypt a message using the a stream
-- cipher. Consider two parties Alice and Bob who share a secret Key
-- @K@. By computing the cipher text @C@ for a message @M@ using the
-- this shared secret key @K@ and a nounce @N@, Alice can guarantee
-- that no one else other than Bob can decrypt this message. While the
-- key needs to be secret, there is no such requirement for the nounce
-- except that using the same (key, nounce) pair to multiple messages
-- can leak information. The nounce is large enough so that a simple
-- strategy of picking it uniformly at random should suffice.
--
-- == Warning
--
-- This module, although sufficiently high level, gives a false sense
-- of security:
--
-- 1. Encryption alone is almost always not sufficient when the goal
--    is secure communication between Alice and Bob. If your aim is
--    secure communication, consider using authenticated encryption
--    provided by "Raaz.AuthEncrypt".
--
-- 2. Under no circumstances should the key, nounce pair be repeated.
--


-- $specific-encryption$
--
-- If interoperability with other applications demands the use of a
-- specific primitive for message authentication, you can use one of
-- these more specific modules.
--
-- * Raaz.Encrypt.ChaCha20
-- * Raaz.Encrypt.XChaCha20
