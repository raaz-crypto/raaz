-- | Entropy based on `/dev/urandom`.
module Raaz.Entropy( getEntropy, entropySource ) where

import Control.Monad.IO.Class( MonadIO, liftIO)
import System.IO
import Raaz.Core.Prelude
import Raaz.Core



-- | The name of the source from which entropy is gathered. For
-- information purposes only.
entropySource :: String
entropySource = "/dev/urandom(generic posix)"

-- | Get random bytes from the system. Do not over use this function
-- as it is meant to be used by a PRG. This function reads bytes from
-- '/dev/urandom'.
getEntropy :: (MonadIO m, LengthUnit l) => l -> Pointer -> m (BYTES Int)
getEntropy l ptr = liftIO $ withBinaryFile "/dev/urandom" ReadMode $ \ hand -> hFillBuf hand ptr l
