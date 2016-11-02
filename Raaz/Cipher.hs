-- | This module exposes all the ciphers provided by raaz. The
-- interface here is pretty low level and it is usually the case that
-- you would not need to work at this level of detail.
module Raaz.Cipher
       ( -- * Ciphers
         -- $cipherdoc$
         Cipher
       , aes128cbc, aes192cbc, aes256cbc
       , StreamCipher
       , chacha20, transform
       ) where


import Raaz.Cipher.AES      ( aes128cbc, aes192cbc, aes256cbc)
import Raaz.Cipher.ChaCha20
import Raaz.Cipher.Internal (transform, Cipher, StreamCipher)

-- $cipherdoc$
--
-- The raaz library exposes symmetric key encryption using instances
-- of the class `Cipher`. For a cipher @c@, the type family @`Key` c@
-- gives the type of its key.
