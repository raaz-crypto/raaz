{-|

This module provides the message authentication abstraction

-}

{-# LANGUAGE TypeFamilies     #-}
{-# LANGUAGE FlexibleContexts #-}
module Raaz.MAC
       ( CryptoMAC(..)
       , withMACCxt
       , mac
       , macLazy
       ) where

import Control.Exception(finally)
import Control.Monad(foldM)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import System.IO.Unsafe(unsafePerformIO)

import Raaz.Types(CryptoStore, CryptoPtr)

-- | The class that captures a cryptographic message authentication
-- algorithm. The associated type @MAC m@ captures the actual MAC
-- value.
--
-- [Warning] While defining the @'Eq'@ instance of @'MAC' h@, make
-- sure that the @==@ operator takes time independent of the input.
-- This is to avoid timing based side-channel attacks. In particular
-- /do not/ take the lazy option of deriving the @'Eq'@ instance.
--

class ( Eq          (MAC m)
      , CryptoStore (MAC m)
      ) => CryptoMAC m where

  -- | The MAC value.
  data MAC m   :: *

  -- | The secret key
  type MACSecret m :: *

  -- | The MAC context.
  type MACCxt m :: *

  -- | The size of message blocks in bytes.
  macBlockSize  :: m -> Int

  -- | Alloc a new context for use.
  newMACCxt     :: m -> MACSecret m ->  IO (MACCxt m)

  -- | Free the resource associated with a context. Use of the context
  -- again leads to undefined behaviour.
  freeMACCxt    :: m -> MACCxt m -> IO ()

  -- | Resets the context for reuse in the next MAC computation.
  resetMACCxt   :: m              -- ^ The mac algorithm
                -> MACSecret m    -- ^ The secret
                -> MACCxt m       -- ^ The MAC context
                -> IO (MACCxt m)

  -- | Add the next chunk of data.
  addMACData    :: m -> MACCxt m -> B.ByteString -> IO (MACCxt m)

  -- | Finalise the context to a MAC value.
  finaliseMAC   :: m -> MACCxt m -> IO (MAC m)

  -- | For data that is of size, which is a multiple of the block size
  -- of the MAC, you can use this potentially faster method of
  -- updating the context. This method is guranteed to generate the
  -- correct output only when the number of bytes processed in the
  -- context so far is also a multiple of the block size.
  unsafeAddMACData :: m
                   -> MACCxt m  -- ^ The MAC context
                   -> CryptoPtr -- ^ The pointer to the first element
                   -> Int       -- ^ Number of MAC blocks (not the
                                -- number of bytes).
                   -> IO (MACCxt m)

-- | Run a computation using a hash cxt
withMACCxt :: CryptoMAC m
           => m
           -> MACSecret m
           -> (MACCxt m -> IO a)  -- ^ The action to run
           -> IO a
withMACCxt m secret act = do cxt <- newMACCxt m secret
                             act cxt `finally` freeMACCxt m cxt


-- | Compute the mac of a strict byte string message.
mac :: CryptoMAC m
    => m
    -> MACSecret m
    -> B.ByteString
    -> MAC m
mac m secret bs = unsafePerformIO $ withMACCxt m secret act
    where act cxt = addMACData m cxt bs >>= finaliseMAC m


-- | Compute the mac of a lazy byte string message.
macLazy :: CryptoMAC m
        => m
        -> MACSecret m
        -> L.ByteString
        -> MAC m

macLazy m secret lbs = unsafePerformIO $ withMACCxt m secret act
  where act cxt = foldM (addMACData m) cxt (L.toChunks lbs)
                  >>= finaliseMAC m
