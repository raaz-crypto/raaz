module Raaz.Cipher.ChaCha20
       ( chacha20, KEY, IV, Counter
       ) where

import Raaz.Cipher.ChaCha20.Internal
import Raaz.Cipher.ChaCha20.Recommendation()

-- | The chacha20 stream cipher.
chacha20 :: ChaCha20
chacha20 = ChaCha20
