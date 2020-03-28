-- | The interface is the same as that of "Raaz.Encrypt" but the
-- primitive selection corresponds to the version 1 of the raaz
-- library. Use this module if you want compatibility with Version 1
-- of the library.
--
-- For documentation refer the module "Raaz.Encrypt".

module Raaz.V1.Encrypt ( Cipher
                       , encrypt, decrypt
                       , encryptAt, decryptAt
                       ) where

import           Data.ByteString
import           Raaz.Core
import           Raaz.Primitive.ChaCha20.Internal   (XChaCha20)
import qualified Raaz.Encrypt.XChaCha20 as XChaCha20

-- import           Raaz.Primitive.ChaCha20.Internal(Blake2b)
-- import           Raaz.Primitive.Keyed.Internal(Keyed)

-- | The message authentication.
type Cipher = XChaCha20

-- | Encrypt using the cipher.
encrypt :: Key Cipher     -- ^ The key for the stream cipher
        -> Nounce Cipher  -- ^ The nounce used by the stream cipher.
        -> ByteString     -- ^ The bytestring to process
        -> ByteString
encrypt = XChaCha20.encrypt

-- | Encryption starting at a given block offset.
encryptAt :: Key Cipher    -- ^
          -> Nounce Cipher
          -> BlockCount Cipher
          -> ByteString
          -> ByteString
encryptAt = XChaCha20.encryptAt

-- | Same as decryption but starting at a given offset.
decryptAt :: Key Cipher
          -> Nounce Cipher
          -> BlockCount Cipher
          -> ByteString
          -> ByteString
decryptAt = XChaCha20.decryptAt

-- | Decrypt the byte string.
decrypt :: Key Cipher
        -> Nounce Cipher
        -> ByteString
        -> ByteString
decrypt = XChaCha20.decrypt
