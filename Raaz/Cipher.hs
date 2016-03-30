-- | This module exposes all the ciphers provided by raaz. The
-- interface here is pretty low level and it is usually the case that
-- you would not need to work at this level of detail.
module Raaz.Cipher
       ( -- * Ciphers
         Cipher, aes128cbc, aes128ctr
         -- ** Unsafe encryption and decryption
       , unsafeEncrypt, unsafeDecrypt
       ) where


import Raaz.Cipher.AES (aes128cbc, aes128ctr)
import Raaz.Cipher.Internal ( Cipher
                            , unsafeEncrypt, unsafeDecrypt
                            )
