{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE MultiParamTypeClasses       #-}
-- | The portable C-implementation of SHA384
module Raaz.Hash.Sha384.Implementation.CPortable
       ( implementation
       ) where

import Control.Applicative
import Raaz.Core
import Raaz.Hash.Internal
import Raaz.Hash.Sha384.Internal
import Raaz.Hash.Sha512.Internal

import qualified Raaz.Hash.Sha512.Implementation.CPortable as SHA512I


newtype SHA384Memory = SHA384Memory { unSHA384Mem :: HashMemory SHA512 }

instance Memory SHA384Memory where
  memoryAlloc   = SHA384Memory <$> memoryAlloc
  underlyingPtr = underlyingPtr . unSHA384Mem

instance Initialisable SHA384Memory () where
  initialise _ = liftSubMT unSHA384Mem
                 $ initialise
                 $ SHA512
                 $ unsafeFromList [ 0xcbbb9d5dc1059ed8
                                  , 0x629a292a367cd507
                                  , 0x9159015a3070dd17
                                  , 0x152fecd8f70e5939
                                  , 0x67332667ffc00b31
                                  , 0x8eb44a8768581511
                                  , 0xdb0c2e0d64f98fa7
                                  , 0x47b5481dbefa4fa4
                                  ]

instance Extractable SHA384Memory SHA384 where
  extract = trunc <$> liftSubMT unSHA384Mem extract
    where trunc (SHA512 v) = SHA384 $ initial v

-- | The portable C implementation of SHA1.
implementation :: Implementation SHA384
implementation =  SomeHashI cPortable

cPortable :: HashI SHA384 SHA384Memory
cPortable = truncatedI fromIntegral unSHA384Mem SHA512I.cPortable
