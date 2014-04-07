{- |

This module exports instances for ECB mode of AES cipher.

In ECB mode, message is divided into blocks and each is encrypted
separately with the same key. Thus identical plain text blocks are
encrypted into identical ciphertext blocks. It doesn't provide serious
message confidentiality, and it is not recommended for use in
cryptographic protocols at all.

<< http://upload.wikimedia.org/wikipedia/commons/thumb/d/d6/ECB_encryption.svg/601px-ECB_encryption.svg.png >>
<< http://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png >>

-}
module Raaz.Cipher.AES.ECB () where

import Raaz.Primitives.Cipher
import Raaz.Cipher.AES.ECB.CPortable ()
import Raaz.Cipher.AES.ECB.Instance  ()
import Raaz.Cipher.AES.ECB.Ref       ()
import Raaz.Cipher.AES.ECB.Type      ()
