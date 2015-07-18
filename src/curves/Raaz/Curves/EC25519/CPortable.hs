{- |

This module gives the recommended implementation of the DH functions
over Curve25519. This uses the curve25519-donna implementation from
https://github.com/agl/curve25519-donna/.

-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CPP                      #-}
{-# CFILES raaz/curves/cportable/curve25519-donna.c #-}

#include "MachDeps.h"

module Raaz.Curves.EC25519.CPortable
        ( params25519Reco,
          sharedSecret25519Reco
        ) where

import Control.Monad   (void)
import Foreign.Ptr
import Foreign.C.Types

import Raaz.Core.Types
import Raaz.Core.Util.Ptr (byteSize, allocaBuffer)
import Raaz.Curves.EC25519.Internal

#if WORD_SIZE_IN_BITS < 64
foreign import ccall unsafe
  "curve25519-donna.c raaz_curve25519_donna_portable"
   c_curve25519_donna :: CryptoPtr -> CryptoPtr -> CryptoPtr -> IO CInt
#else
foreign import ccall unsafe
    "curve25519-donna-c64.c raaz_curve25519_donna_c64"
     c_curve25519_donna :: CryptoPtr -> CryptoPtr -> CryptoPtr -> IO CInt
#endif

-- | Given a random number, generates the secret and publictoken tuple
params25519Reco :: P25519 -> IO (Secret25519, PublicToken25519)
params25519Reco randomnum = do
  let basenum   = integerToP25519 curve25519Gx
      secretnum = randomnum
      szBytes   = byteSize (undefined :: P25519)
      size      = sizeOf (undefined :: P25519)
      totalSize = szBytes * 3
  allocaBuffer totalSize $ \ ptr -> do
    store (ptr `plusPtr` size) secretnum
    store (ptr `plusPtr` (2*size)) basenum
    void $ c_curve25519_donna ptr (ptr `plusPtr` size) (ptr `plusPtr` (2*size))
    pubkey <- load ptr
    secret <- load (ptr `plusPtr` size)
    return (Secret25519 secret, PublicToken25519 pubkey)

-- | Given a secret and public token, generates shared secret
sharedSecret25519Reco :: Secret25519
                       -> PublicToken25519
                       -> IO (SharedSecret25519)
sharedSecret25519Reco (Secret25519 privnum) (PublicToken25519 publicnum) = do
  let basenum   = publicnum
      secretnum = privnum
      szBytes   = byteSize (undefined :: P25519)
      size      = sizeOf (undefined :: P25519)
      totalSize = szBytes * 3
  allocaBuffer totalSize $ \ ptr -> do
    store (ptr `plusPtr` size) secretnum
    store (ptr `plusPtr` (2*size)) basenum
    void $ c_curve25519_donna ptr (ptr `plusPtr` size) (ptr `plusPtr` (2*size))
    sharedkey <- load ptr
    return (SharedSecret25519 sharedkey)
