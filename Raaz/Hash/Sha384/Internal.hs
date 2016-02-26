{-# LANGUAGE CPP                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

module Raaz.Hash.Sha384.Internal
       ( SHA384(..)
       ) where


#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif

import           Data.String
import qualified Data.Vector.Unboxed                  as VU
import           Data.Word
import           Data.Typeable       ( Typeable     )
import           Foreign.Ptr         ( castPtr      )
import           Foreign.Storable    ( Storable(..) )

import           Raaz.Core
import           Raaz.Core.Parse.Applicative
import           Raaz.Core.Write
import           Raaz.Hash.Internal
import qualified Raaz.Hash.Sha512.Internal as Sha512I
import           Raaz.Hash.Sha512.Internal ( SHA512(..) )


----------------------------- SHA384 -------------------------------------------

-- | The Sha384 hash value.
newtype SHA384 = SHA384 (Tuple 6 (BE Word64))
                 deriving (Eq, Equality, Storable, EndianStore)

instance Encodable SHA384

instance IsString SHA384 where
  fromString = fromBase16

instance Show SHA384 where
  show =  showBase16

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

instance Primitive SHA384 where
  blockSize _ = BYTES 128
  type Implementation SHA384 = SomeHashI SHA384
  recommended  _             = SomeHashI cPortable

instance Hash SHA384 where
  additionalPadBlocks _ = 1

------------------- The portable C implementation ------------

cPortable :: HashI SHA384 SHA384Memory
cPortable = truncatedI fromIntegral unSHA384Mem Sha512I.cPortable
