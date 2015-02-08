module Raaz.Core.Types.CryptoBuffer
      ( CryptoBuffer(..), withCryptoBuffer ) where

import Raaz.Core.Classes
-- | Pointers with associated size. Reading and writing under the
-- given size is considered safe.
data CryptoBuffer = CryptoBuffer {-# UNPACK #-} !(BYTES Int)
                                 {-# UNPACK #-} !CryptoPtr

-- | Working on the pointer associated with the `CryptoBuffer`.
withCryptoBuffer :: CryptoBuffer -- ^ The buffer
                 -> (BYTES Int -> CryptoPtr -> IO b)
                                 -- ^ The action to perfrom
                 -> IO b
withCryptoBuffer (CryptoBuffer sz cptr) with = with sz cptr
