-- | Module to write stuff to buffers. This writer provides low level
-- writing of data to memory locations given by pointers. It does the
-- necessary pointer arithmetic to make the pointer point to the next
-- location. No range checks are done to speed up the operations and
-- hence these operations are highly unsafe. Use it with care.
module Raaz.Write
       ( Write
       , runWrite
       , runWriteForeignPtr
       ) where

import Control.Monad               ( (>=>) )
import Data.Monoid
import Foreign.ForeignPtr.Safe     ( withForeignPtr )

import Raaz.Types

-- | The write type.
newtype Write = Write (CryptoPtr -> IO CryptoPtr)

instance Monoid Write where
  mempty                               = Write return
  mappend (Write first) (Write second) = Write (first >=> second)

-- | Perform a write action on a buffer pointed by the crypto pointer.
runWrite :: CryptoPtr -> Write -> IO ()
runWrite cptr (Write action) = action cptr >> return ()

-- | Perform a write action on a buffer pointed by a foreign pointer
runWriteForeignPtr   :: ForeignCryptoPtr -> Write -> IO ()
runWriteForeignPtr fptr (Write action) = withForeignPtr fptr action
                                         >> return ()
