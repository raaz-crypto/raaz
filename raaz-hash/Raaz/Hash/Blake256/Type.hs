{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Raaz.Hash.Blake256.Type
       ( BLAKE256(..)
       , Salt(..)
       , BLAKEMem(..)
       ) where

import           Control.Applicative ( (<$>) )
import qualified Data.Vector.Unboxed                  as VU
import           Data.Word
import           Data.Typeable       ( Typeable     )
import           Foreign.Ptr         ( castPtr      )
import           Foreign.Storable    ( Storable(..) )

import           Raaz.Core.Memory
import           Raaz.Core.Classes
import           Raaz.Core.Parse.Applicative
import           Raaz.Core.Primitives
import           Raaz.Core.Types
import           Raaz.Core.Write

import           Raaz.Hash.Blake.Util

------------------------------------BLAKE256----------------------------------

-- | The Blake256 hash value.
data BLAKE256 = BLAKE256 (VU.Vector (BE Word32)) deriving ( Show, Typeable )

-- | The Blake256 salt value.
data Salt = Salt (VU.Vector (BE Word32)) deriving ( Show, Typeable )

-- | Timing independent equality testing for Blake256
instance Eq BLAKE256 where
 (==) (BLAKE256 g) (BLAKE256 h) = oftenCorrectEqVector g h

instance Eq Salt where
 (==) (Salt g) (Salt h) = oftenCorrectEqVector g h

instance HasName BLAKE256

instance Storable BLAKE256 where
  sizeOf    _ = 8 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))

  peek = unsafeRunParser blake256parse . castPtr
    where blake256parse = BLAKE256 <$> unsafeParseStorableVector 8

  poke ptr (BLAKE256 v) = unsafeWrite writeBLAKE256 cptr
    where writeBLAKE256 = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore BLAKE256 where
  load = unsafeRunParser $ BLAKE256 <$> unsafeParseVector 8

  store cptr (BLAKE256 v) = unsafeWrite writeBLAKE256 cptr
    where writeBLAKE256 = writeVector v

instance Storable Salt where
  sizeOf    _ = 4 * sizeOf (undefined :: (BE Word32))
  alignment _ = alignment  (undefined :: (BE Word32))

  peek ptr = do
    let parseSalt = unsafeParseStorableVector $ sizeOf (undefined :: Salt)
        cptr = castPtr ptr
    parserV <- unsafeRunParser parseSalt cptr
    return $ Salt parserV

  poke ptr (Salt v) = unsafeWrite writeSalt cptr
    where writeSalt = writeStorableVector v
          cptr = castPtr ptr

instance EndianStore Salt where
  load cptr = do
    let parseSalt = unsafeParseVector $ sizeOf (undefined :: Salt)
    parserV <- unsafeRunParser parseSalt cptr
    return $ Salt parserV

  store cptr (Salt v) = unsafeWrite writeSalt cptr
    where writeSalt = writeVector v

instance Primitive BLAKE256 where
  blockSize _ = BYTES 64
  {-# INLINE blockSize #-}
  type Key BLAKE256 = (BLAKE256, Salt)

instance SafePrimitive BLAKE256

instance HasPadding BLAKE256 where
  maxAdditionalBlocks _ = 1
  padLength = blakePadLength 8
  padding   = blakePadding   8

-- | Memory for BLAKE. It stores three things
--
-- 1. Blake hash value for data processed so far
-- 2. Salt used
-- 3. Counter of bits hashed so far
--
newtype BLAKEMem blake = BLAKEMem (CryptoCell blake, CryptoCell Salt, CryptoCell (BITS Word64))
                       deriving Memory

instance Storable blake => InitializableMemory (BLAKEMem blake) where

  type IV (BLAKEMem blake) = (blake, Salt)

  initializeMemory (BLAKEMem (cblake, csalt, ccounter)) (blake,salt) = do
    cellPoke cblake blake
    cellPoke csalt salt
    cellPoke ccounter 0

instance Storable blake => FinalizableMemory (BLAKEMem blake) where

  type FV (BLAKEMem blake) = (blake, Salt)

  finalizeMemory (BLAKEMem (cblake, csalt, _)) = do
    blake <- cellPeek cblake
    salt <- cellPeek csalt
    return (blake, salt)
