-- |
-- Module      : Raaz.AuthEncrypt.Unsafe
-- Copyright   : (c) Piyush P Kurur, 2016
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
module Raaz.AuthEncrypt.Unsafe
       ( -- * Auth Encryption with Explicit Nounce
         -- $unsafe$
         -- ** Specific variants
         -- $specific$
         module Raaz.V1.AuthEncrypt.Unsafe
       ) where

import Raaz.V1.AuthEncrypt.Unsafe

-- $unsafe$
--
-- __WARNING:__ The security of the interface is compromised if
--
-- 1. The key gets revealed to the attacker or
--
-- 2. If the same key/nounce pair is used to lock two different
--    messages.
--
-- 3. Taking apart the AEAD token also compromises the type safety.
--
-- Why then do we provide these functions ? As long as you are using
-- the raaz library exclusively, you do not need to use this unsafe
-- function. These are only needed when working with other libraries
-- and protocols which have a different nonunce selection policy
-- and/or a different encoding scheme for the AEAD token.
--
-- Nounces need not be private and may be exposed to the attacker. In
-- fact, in the safe version of these locking function, we pick the
-- nounce at random (using the csprg) and pack it into the AEAD token.

-- $specific$
--
-- For specific algorithms, the unsafe version is also available
--
-- * Raaz.AuthEncrypt.Unsafe.ChaCha20Poly1305
-- * Raaz.AuthEncrypt.Unsafe.XChaCha20Poly1305
--
-- The former has a smaller nounce (96-bits) than the latter
-- (192-bits) and hence there is a slight risk in using it with
-- randomly generated nounces. It is however, slightly faster and is
-- safe to use when there is frequent key resets as in the case of
-- network protocols. As with other cases we recommend the use of the
-- default interface instead of the specific one when ever possible.
