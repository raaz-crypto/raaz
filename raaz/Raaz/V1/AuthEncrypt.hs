-- |
-- Module      : Raaz.V1.AuthEncrypt
-- Copyright   : (c) Piyush P Kurur, 2016
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
module Raaz.V1.AuthEncrypt
  ( -- * Encrypted authentication from V1
    --
    -- The interface is the same as that of "Raaz.AuthEncrypt" but with the
    -- primitive selection corresponding to the version 1 of the raaz
    -- library. Use this module if you want compatibility with Version 1
    -- of the library.
    --
    -- For documentation refer the module "Raaz.AuthEncrypt".
    lock, unlock
  , lockWith, unlockWith
  , Locked, Cipher
  , authEncryptAlgorithm
  ) where

import           Raaz.Core
import           Raaz.Random                        (random, withRandomState)
import qualified Raaz.AuthEncrypt.Unsafe.XChaCha20Poly1305 as AE
import           Raaz.V1.AuthEncrypt.Unsafe

-- | This function locks a plain text message together with and
-- additional authenticated data to produce an AEAD token. A peer
-- who has the right @key@ and the additional authenticated data can
-- recover the unencrypted object using the `unlockWith` function.
--
-- Unlike `unsafeLockWith`, this function does not require a nounce as
-- internally a random nounce is generated and used each time. As a
-- result we do not put any restriction on the key used; it is safe
-- to use the same key multiple times.

lockWith :: (Encodable plain, Encodable aad)
         => aad              -- ^ the authenticated additional data.
         -> Key Cipher       -- ^ The key
         -> plain            -- ^ the unencrypted object
         -> IO Locked
lockWith aad key plain =
  withRandomState $ \ rstate -> do
  nounce <- random rstate
  return $ unsafeLockWith aad key nounce plain

-- | Unlock an encrypted authenticated version of the data given the
-- additional data, key, and nounce. An attempt to unlock the element
-- can result in `Nothing` if either of the following is true.
--
-- 1. The key/nounce used to encrypt the data is different
--
-- 2. The Authenticated additional data (@aad@) is incorrect
--
-- 3. The cipher text is of the wrong type and hence the
--    `fromByteString` failed
--
-- 4. The Locked message has been tampered with by the adversary
--
-- The interface provided does not indicate which of the above
-- failures had happened. This is a deliberate design as revealing the
-- nature of the failure can leak information to a potential attacker.
--
unlockWith :: (Encodable plain, Encodable aad)
           => aad              -- ^ the authenticated additional data.
           -> Key Cipher       -- ^ The key for the stream cipher
           -> Locked          -- ^ The message to unlock
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
     -> IO Locked
lock = lockWith ()

-- | Unlock the locked version of an object. You will need the exact
-- same key that was used to lock the object.
unlock :: Encodable plain
       => Key Cipher   -- ^ The key
       -> Locked       -- ^ Locked object that needs unlocking
       -> Maybe plain
unlock = AE.unlock

-- | Algorithm used for authenticated encryption
authEncryptAlgorithm :: String
authEncryptAlgorithm = AE.primName
