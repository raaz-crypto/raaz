-- |
-- Module      : Raaz.AuthEncrypt.Unsafe
-- Copyright   : (c) Piyush P Kurur, 2016
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
module Raaz.V1.AuthEncrypt.Unsafe
       ( Locked, AEAD
       , unsafeLock, unsafeLockWith
       , Cipher, AuthTag
       , unsafeToCipherText, unsafeToAuthTag
       , unsafeAEAD
       ) where

import           Data.ByteString
import           Raaz.Core
import qualified Raaz.AuthEncrypt.Unsafe.XChaCha20Poly1305 as AE
import           Raaz.AuthEncrypt.Unsafe.XChaCha20Poly1305 ( AEAD, Locked, Cipher, AuthTag
                                                           )

-- | Similar to `lockWith` but an explicit nounce is taken as
-- input. Reusing the key-nounce pair will compromise the security and
-- hence using this function is unsafe. The user needs to ensure the
-- freshness of the key, nounce pair through some other means.
--
-- Some protocols have a predefined way to pick nounces and this is
-- the reason, we provide such an interface. If that is not a concern,
-- we recommend the use of `lockWith` instead.
unsafeLockWith :: ( Encodable plain, Encodable aad)
               => aad
               -> Key Cipher
               -> Nounce Cipher
               -> plain
               -> AEAD plain aad
unsafeLockWith = AE.unsafeLockWith

-- | Locks a given message but needs an explicit nounce. Reusing the
-- key-nounce pair will compromise the security and hence using this
-- function is unsafe. The user needs to ensure the freshness of the
-- key, nounce pair through some other means.
--
-- Some protocols have a predefined way to pick nounces and this is
-- the reason we provide such an interface. If that is not a concern,
-- we recommend the use of `lock` instead.
unsafeLock :: Encodable plain
           => Key Cipher        -- ^ The key
           -> Nounce Cipher     -- ^ The nounce
           -> plain             -- ^ The object to be locked.
           -> Locked plain
unsafeLock = AE.unsafeLock




-- | Get the cipher text part of the Locked/AEAD packet.
unsafeToCipherText :: AEAD plain aad
                   -> ByteString
unsafeToCipherText = AE.unsafeToCipherText

-- | Get the authentication token of the Locked/AEAD packet.
unsafeToAuthTag :: AEAD plain aad -> AE.AuthTag
unsafeToAuthTag = AE.unsafeToAuthTag


-- | Construct an AEAD packet out of the authentication token and the
-- cipher text.
unsafeAEAD :: Nounce Cipher
           -> ByteString
           -> AE.AuthTag
           -> AEAD plain aad
unsafeAEAD = AE.unsafeAEAD
