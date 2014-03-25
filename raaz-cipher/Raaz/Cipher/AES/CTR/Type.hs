{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Raaz.Cipher.AES.CTR.Type where

import qualified Data.ByteString              as BS
import           Foreign.Storable             (sizeOf)
import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Types
import           Raaz.Util.ByteString

import           Raaz.Cipher.AES.Block.Internal
import           Raaz.Cipher.AES.Internal


instance Primitive (Cipher (AES CTR) k e) where
  blockSize _ = cryptoCoerce $ BITS (8 :: Int)
  {-# INLINE blockSize #-}
  newtype Cxt (Cipher (AES CTR) k e) = AESCxt (k, STATE) deriving Eq

instance EndianStore k => Initializable (Cipher (AES CTR) k e) where
  cxtSize _ = BYTES (ksz + ssz)
    where
      ksz = sizeOf (undefined :: k)
      ssz = sizeOf (undefined :: STATE)
  {-# INLINE cxtSize #-}
  getCxt = AESCxt . getCxtCTR
    where
      getCxtCTR bs = (k,fromByteString ivbs)
        where
          k = fromByteString kbs
          (kbs,ivbs) = BS.splitAt (sizeOf k) bs
