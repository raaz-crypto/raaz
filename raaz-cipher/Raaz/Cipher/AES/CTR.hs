{- |

This module exports instances for CTR mode of AES cipher.

Counter mode turns a block cipher into a stream cipher. It generates
the next keystream block by encrypting successive values of a
counter. The counter can be any function which produces a sequence
which is guaranteed not to repeat for a long time, although an actual
increment-by-one counter is the simplest and most popular.

<< http://upload.wikimedia.org/wikipedia/commons/thumb/4/4d/CTR_encryption_2.svg/601px-CTR_encryption_2.svg.png >>
<< http://upload.wikimedia.org/wikipedia/commons/thumb/3/3c/CTR_decryption_2.svg/601px-CTR_decryption_2.svg.png >>

-}

module Raaz.Cipher.AES.CTR (CTR) where

import Raaz.Primitives.Cipher
import Raaz.Cipher.AES.CTR.CPortable ()
import Raaz.Cipher.AES.CTR.Instance  ()
import Raaz.Cipher.AES.CTR.Ref       ()
import Raaz.Cipher.AES.CTR.Type      ()
