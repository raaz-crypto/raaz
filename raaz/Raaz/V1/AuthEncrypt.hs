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
    -- * Unsafe interfaces
    -- $unsafeinterface$
  , unsafeLock, unsafeLockWith
  , unsafeAEAD
  , unsafeToCipherText
  , unsafeToAuthTag
  ) where

import           Data.ByteString

import           Raaz.Core
import qualified Raaz.AuthEncrypt.XChaCha20Poly1305 as AE
import           Raaz.AuthEncrypt.XChaCha20Poly1305 (AEAD, Locked, Cipher)
import           Raaz.Random                        (random, withRandomState)

-- | This function locks a plain text message together with and
-- additional authenticated data to produce an constructs the AEAD
-- token. A peer who has the right @key@ and the additional
-- authenticated data can recover the unencrypted object using the
-- `unlockWith` function.
--
-- Unlike `unsafeLockWith`, this function does not require a nounce as
-- internally a random nounce is generated and used each time. As a
-- result we do not put any restriction on the key used ; it is safe
-- to use the same key multiple times.

lockWith :: (Encodable plain, Encodable aad)
         => aad              -- ^ the authenticated additional data.
         -> Key Cipher       -- ^ The key
         -> plain            -- ^ the unencrypted object
         -> IO (AEAD plain aad)
lockWith aad key plain =
  withRandomState $ \ rstate -> do
  nounce <- random rstate
  return $ unsafeLockWith aad key nounce plain

-- | Similar to `lockWith` but an explicit nounce is taken as
-- input. Reusing the key-nounce pair will compromise the security and
-- hence using this function is unsafe. The user needs to ensure the
-- freshness of the key, nounce pair through some other means.
--
-- Some protocols have a predefined way to pick nounces and this is
-- the reason, we provide such an interface. If that is not a concern,
-- we recommend the use of `lockWith` instead.
unsafeLockWith :: (Encodable plain, Encodable aad)
               => aad
               -> Key Cipher
               -> Nounce Cipher
               -> plain
               -> AEAD plain aad
unsafeLockWith = AE.unsafeLockWith

-- | Unlock an encrypted authenticated version of the data given the
-- additional data, key, and nounce. An attempt to unlock the element
-- can result in `Nothing` if either of the following is true.
--
-- 1. The key/nounce used to encrypt the data is different
--
-- 2. The Authenticated additional data (@aad@) is incorrect
--
-- 3. The AEAD is of the wrong type and hence the fromByteString failed
--
-- 4. The AEAD value has been tampered with by the adversary
--
-- The interface provided does not indicate which of the above
-- failures had happened. This is a deliberate design as revealing the
-- nature of the failure can leak information to a potential attacker.
--
unlockWith :: (Encodable plain, Encodable aad)
           => aad              -- ^ the authenticated additional data.
           -> Key Cipher       -- ^ The key for the stream cipher
           -> AEAD plain aad   -- ^ The encrypted authenticated version of the data.
           -> Maybe plain
unlockWith = AE.unlockWith


-- | Generate a locked version of an unencrypted object. You will need
-- the exact same key to `unlock` the object. Unlike `unsafelock`,
-- this function does not require a nounce as internally a random
-- nounce is generated and used each time. Because of this, it is safe
-- to use the same key multiple times.
lock :: Encodable plain
     => Key Cipher        -- ^ The key
     -> plain             -- ^ The object to be locked.
     -> IO (Locked plain)
lock = lockWith ()



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


-- | Unlock the locked version of an object. You will need the exact
-- same key that was used to lock the object.
unlock :: Encodable plain
       => Key Cipher      -- ^ The key
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
unsafeAEAD :: Nounce Cipher
           -> ByteString
           -> AE.Auth
           -> AEAD plain aad
unsafeAEAD = AE.unsafeAEAD
