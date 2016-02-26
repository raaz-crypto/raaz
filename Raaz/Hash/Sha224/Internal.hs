{-|

This module exposes the `SHA224` hash constructor. You would hardly
need to import the module directly as you would want to treat the
`SHA224` type as an opaque type for type safety. This module is
exported only for special uses like writing a test case or defining a
binary instance etc.

-}

{-# LANGUAGE CPP                        #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DataKinds                  #-}

module Raaz.Hash.Sha224.Internal
       ( SHA224(..)
       ) where


#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif


import           Data.String
import           Data.Word
import           Foreign.Storable          ( Storable )

import           Raaz.Core
import           Raaz.Hash.Internal
import qualified Raaz.Hash.Sha256.Internal as Sha256I
import           Raaz.Hash.Sha256.Internal ( SHA256(..) )

----------------------------- SHA224 -------------------------------------------

-- | Sha224 hash value which consist of 7 32bit words.
newtype SHA224 = SHA224 (Tuple 7 (BE Word32))
            deriving (Eq, Equality, Storable, EndianStore)

instance Encodable SHA224

instance IsString SHA224 where
  fromString = fromBase16

instance Show SHA224 where
  show =  showBase16

newtype SHA224Memory = SHA224Memory { unSHA224Mem :: HashMemory SHA256 }

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

instance Primitive SHA224 where
  blockSize _                = BYTES 64
  type Implementation SHA224 = SomeHashI SHA224
  recommended  _             = SomeHashI cPortable

instance Hash SHA224 where
  additionalPadBlocks _ = 1

------------------- The portable C implementation ------------

cPortable :: HashI SHA224 SHA224Memory
cPortable = truncatedI fromIntegral unSHA224Mem Sha256I.cPortable
