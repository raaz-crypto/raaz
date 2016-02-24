{-|

This module exposes the `SHA224` hash constructor. You would hardly
need to import the module directly as you would want to treat the
`SHA224` type as an opaque type for type safety. This module is
exported only for special uses like writing a test case or defining a
binary instance etc.

-}


{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE ForeignFunctionInterface   #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# CFILES raaz/hash/sha1/portable.c    #-}

module Raaz.Hash.Sha224.Internal
       ( SHA224(..)
       ) where

import           Control.Applicative ( (<$>) )
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
import qualified Raaz.Hash.Sha256.Internal as Sha256I
import           Raaz.Hash.Sha256.Internal ( SHA256(..) )

----------------------------- SHA224 -------------------------------------------

-- | Sha224 hash value which consist of 7 32bit words.
data SHA224 = SHA224 (VU.Vector (BE Word32)) deriving Typeable

-- | Timing independent equality testing for sha224
instance Eq SHA224 where
 (==) (SHA224 g) (SHA224 h) = oftenCorrectEqVector g h


instance Storable SHA224 where
  sizeOf    _ = 7 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))

  peek = unsafeRunParser sha224parse . castPtr
    where sha224parse = SHA224 <$> unsafeParseStorableVector 7

  poke ptr (SHA224 v) = unsafeWrite writeSHA224 cptr
    where writeSHA224 = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore SHA224 where
  load = unsafeRunParser $ SHA224 <$> unsafeParseVector 7

  store cptr (SHA224 v) = unsafeWrite writeSHA224 cptr
    where writeSHA224 = writeVector v


instance Encodable SHA224

instance IsString SHA224 where
  fromString = fromBase16

instance Show SHA224 where
  show =  showBase16

newtype SHA224Memory = SHA224Memory { unSHA224Mem :: HashMemory SHA256 }
                     deriving Memory

instance Initialisable SHA224Memory () where
  initialise _ = liftSubMT unSHA224Mem $
                 initialise $ SHA256 $ VU.fromList [ 0xc1059ed8
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
    where trunc :: SHA256 -> SHA224
          trunc (SHA256 v) = SHA224 (VU.slice 0 7 v)

instance Primitive SHA224 where
  blockSize _                = BYTES 64
  type Implementation SHA224 = SomeHashI SHA224
  recommended  _             = SomeHashI cPortable

instance Hash SHA224 where
  additionalPadBlocks _ = 1


------------------- The portable C implementation ------------

cPortable :: HashI SHA224 SHA224Memory
cPortable = truncatedI fromIntegral unSHA224Mem Sha256I.cPortable
