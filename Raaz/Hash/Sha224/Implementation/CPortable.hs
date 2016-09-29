{-# LANGUAGE MultiParamTypeClasses      #-}
-- | The portable C-implementation of SHA224
module Raaz.Hash.Sha224.Implementation.CPortable
       ( implementation
       ) where

import Control.Applicative
import Prelude

import Raaz.Core
import Raaz.Hash.Internal
import Raaz.Hash.Sha224.Internal

import           Raaz.Hash.Sha256.Internal ( SHA256(..) )
import qualified Raaz.Hash.Sha256.Implementation.CPortable as SHA256I


newtype SHA224Memory  = SHA224Memory { unSHA224Mem :: HashMemory SHA256 }

instance Memory SHA224Memory where
  memoryAlloc   = SHA224Memory <$> memoryAlloc
  underlyingPtr = underlyingPtr . unSHA224Mem

instance Initialisable SHA224Memory () where
  initialise _ = liftSubMT unSHA224Mem $
                 initialise $ SHA256 $ unsafeFromList [ 0xc1059ed8
                                                      , 0x367cd507
                                                      , 0x3070dd17
                                                      , 0xf70e5939
                                                      , 0xffc00b31
                                                      , 0x68581511
                                                      , 0x64f98fa7
                                                      , 0xbefa4fa4
                                                      ]

instance Extractable SHA224Memory SHA224 where
  extract = trunc <$> liftSubMT unSHA224Mem extract
    where trunc (SHA256 tup) = SHA224 $ initial tup

-- | The portable C implementation of SHA224.
implementation :: Implementation SHA224
implementation =  SomeHashI cPortable

cPortable :: HashI SHA224 SHA224Memory
cPortable = truncatedI fromIntegral unSHA224Mem SHA256I.cPortable
