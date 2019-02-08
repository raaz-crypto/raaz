{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TypeFamilies               #-}

-- | The keyed version of a primitive (typically cryptographic
-- hash). Certain hashes like blake2 can be used for message
-- authentication where the message is essentially appended to the key
-- and hashed. This module is meant to handle such keyed primitives.
-- Note that this naive message authentication is vulnerable to length
-- extension attack when combined with a Merkel-Damgrad like hash like
-- the sha2 family of hashes; they require a more complicated HMAC
-- construction.
module Raaz.Primitive.Keyed.Internal
       ( Keyed(..), KeyedHash(..), unsafeToKeyed, unsafeToPrim
       , trim, trimLength
       ) where

import Data.ByteString  as BS
import Data.Proxy       ( Proxy    )
import Data.String
import Foreign.Storable ( Storable )

import Raaz.Core

-- | Class of primitives, typically cryptographic hashes, that when
-- used as a keyed hash gives a safe MAC.
class (Primitive prim, Storable prim) => KeyedHash prim where
  -- The initialisation used by the hash can depend on the length of
  -- the key used.
  hashInit :: BYTES Int -> prim


trim :: Storable prim => Proxy prim -> Keyed ByteString -> BS.ByteString
trim proxy (Keyed keyBS) = BS.take sz keyBS
  where sz = fromEnum $ trimLength proxy

trimLength :: Storable prim => Proxy prim -> BYTES Int
trimLength proxy = sizeOf proxy


-- | The message authentication code associated with the hashes.
newtype Keyed prim = Keyed prim
                 deriving (Eq, Equality, Storable, EndianStore, Encodable)


type instance Key (Keyed prim) = Keyed ByteString

-- | Converts a Keyed value to the corresponding hash value. This
-- function violates the principle that semantically distinct values
-- should be of distinct types and hence should be considered unsafe
unsafeToPrim :: Keyed prim -> prim
unsafeToPrim (Keyed p) = p


-- | Converts the hash value to the corresponding @`Keyed`@
-- value. This function violates the principle that semantically
-- distinct values should be of distinct types and hence should be
-- considered unsafe.
unsafeToKeyed :: prim -> Keyed prim
unsafeToKeyed = Keyed

instance IsString prim => IsString (Keyed prim) where
  fromString = unsafeToKeyed . fromString

instance Show prim => Show (Keyed prim) where
  show = show . unsafeToPrim

instance Primitive prim => Primitive (Keyed prim) where
  type BlockSize (Keyed prim) = BlockSize prim
