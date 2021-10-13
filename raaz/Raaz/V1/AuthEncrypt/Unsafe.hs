-- |
-- Module      : Raaz.AuthEncrypt.Unsafe
-- Copyright   : (c) Piyush P Kurur, 2016
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
module Raaz.V1.AuthEncrypt.Unsafe
       ( Locked
       , unsafeLock, unsafeLockWith
       , Cipher, AuthTag
       , unsafeToNounce, unsafeToCipherText, unsafeToAuthTag
       , unsafeLocked
       ) where

import           Data.ByteString
import           Raaz.Core
import qualified Raaz.AuthEncrypt.Unsafe.XChaCha20Poly1305 as AE
import           Raaz.AuthEncrypt.Unsafe.XChaCha20Poly1305 ( Locked, Cipher, AuthTag
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
               -> Locked
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
           -> Locked
unsafeLock = AE.unsafeLock




-- | Get the cipher text part of the Locked message.
unsafeToCipherText :: Locked
                   -> ByteString
unsafeToCipherText = AE.unsafeToCipherText

-- | Get the authentication token of the Locked message.
unsafeToAuthTag :: Locked -> AE.AuthTag
unsafeToAuthTag = AE.unsafeToAuthTag

-- | Get the nounce used for authenticating the token.
unsafeToNounce :: Locked -> Nounce Cipher
unsafeToNounce = AE.unsafeToNounce

-- | Construct the locked message out of the nounce, cipher text, and the
-- authentication tag.
unsafeLocked :: Nounce Cipher  -- ^ The nounce used for locking this message
             -> ByteString     -- ^ The cipher text
             -> AE.AuthTag     -- ^ the Authentication tag
             -> Locked
unsafeLocked = AE.unsafeLocked
