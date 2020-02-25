-- | The interface is the same as that of "Raaz.EncryptAuth" but the
-- primitive selection corresponds to the version 1 of the raaz
-- library. Use this module if you want compatibility with Version 1
-- of the library.
--
-- For documentation refer the module "Raaz.AuthEncrypt".

module Raaz.V1.AuthEncrypt
  ( lock, unlock
  , lockWith, unlockWith
  , AEAD, Locked
  , unsafeAEAD
  , unsafeToCipherText
  , unsafeToAuthTag
  ) where

import           Data.ByteString

import           Raaz.Core
import qualified Raaz.AuthEncrypt.XChaCha20Poly1305 as AE
import           Raaz.AuthEncrypt.XChaCha20Poly1305 (AEAD, Locked, Cipher)

-- | This function takes the plain text and the additional data, and
-- constructs the AEAD token. A peer who has the right @(key, nounce)@
-- pair and the `aad` can recover the unencrypted object using the
-- `unlockWith` function.
lockWith :: (Encodable plain, Encodable aad)
        => aad              -- ^ the authenticated additional data.
        -> Key Cipher       -- ^ The key
        -> Nounce Cipher    -- ^ The nounce
        -> plain            -- ^ the unencrypted object
        -> AEAD plain aad
lockWith = AE.lockWith

-- | Unlock an encrypted authenticated version of the data given the
-- additional data, key, and nounce. An attempt to unlock the element
-- can result in `Nothing` if either of the following is true.
--
-- 1. The key, nounce pair used to encrypt the data is different
-- 2. The Authenticated additional data (@aad@) is incorrect
-- 3. The AEAD is of the wrong type and hence the fromByteString failed
-- 4. The AEAD value has been tampered with by the adversery
--
-- The interface provided does not indicate which of the above
-- failures had happened. This is a deliberate design as revealing the
-- nature of the failure can leak information to a potential attacker.
--
unlockWith :: (Encodable plain, Encodable aad)
           => aad              -- ^ the authenticated additional data.
           -> Key Cipher       -- ^ The key for the stream cipher
           -> Nounce Cipher    -- ^ The nounce used by the stream cipher.
           -> AEAD plain aad   -- ^ The encrypted authenticated version of the data.
           -> Maybe plain
unlockWith = AE.unlockWith


-- | Generate a locked version of an unencrypted object. You will need
-- the exact same key and nounce to `unlock` the object.
lock :: Encodable plain
     => Key Cipher        -- ^ The key
     -> Nounce Cipher     -- ^ The nounce
     -> plain             -- ^ The object to be locked.
     -> Locked plain
lock = AE.lock


-- | Unlock the locked version of an object. You will need the exact
-- same key and nounce that was used to lock the object.
unlock :: Encodable plain
       => Key Cipher      -- ^ The key
       -> Nounce Cipher   -- ^ The nounce
       -> Locked plain    -- ^ Locked object that needs unlocking
       -> Maybe plain
unlock = AE.unlock


-- | Get the cipher text part of the Locked/AEAD packet.
unsafeToCipherText :: AEAD plain aad
                   -> ByteString
unsafeToCipherText = AE.unsafeToCipherText

-- | Get the authentication token of the Locked/AEAD packet.
unsafeToAuthTag :: AEAD plain aad -> AE.Auth
unsafeToAuthTag = AE.unsafeToAuthTag


-- | Construct an AEAD packet out of the authentication token and the
-- cipher text.
unsafeAEAD :: AE.Auth
           -> ByteString
           -> AEAD plain aad
unsafeAEAD = AE.unsafeAEAD
