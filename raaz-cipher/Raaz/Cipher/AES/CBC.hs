{- |

This module exports instances for CBC mode of AES cipher.

In CBC mode, each block of plaintext is XORed with the previous
ciphertext block before being encrypted. This way, each ciphertext
block depends on all plaintext blocks processed up to that point. To
make each message unique, an initialization vector must be used in the
first block.

<< http://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/601px-CBC_encryption.svg.png >>
<< http://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/601px-CBC_decryption.svg.png >>


-}
module Raaz.Cipher.AES.CBC () where

import Raaz.Primitives.Cipher
import Raaz.Cipher.AES.CBC.CPortable ()
import Raaz.Cipher.AES.CBC.Instance  ()
import Raaz.Cipher.AES.CBC.Ref       ()
import Raaz.Cipher.AES.CBC.Type      ()
