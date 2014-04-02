{-# LANGUAGE DeriveDataTypeable #-}
module Raaz.RSA.Types
       ( Octet, xorOctet
       , PublicKey (..)
       , PrivateKey (..)
       , MGF
       )where

import           Raaz.Hash.Sha1
import           Raaz.Hash.Sha256
import           Raaz.Hash.Sha384
import           Raaz.Hash.Sha512
import           Raaz.Types

import           Data.Bits
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Typeable

type Octet = ByteString

xorOctet :: Octet -> Octet -> Octet
xorOctet o1 o2 = BS.pack $ BS.zipWith xor o1 o2

-- | RSA Public Key
data PublicKey = PublicKey
                 { pubSize :: BYTES Int   -- ^ Size of modulus n in BYTES
                 , pubN    :: Integer     -- ^ n
                 , pubE    :: Integer     -- ^ e
                 } deriving (Show, Typeable)

-- | RSA Private Key
data PrivateKey = PrivateKey
                  { privSize :: BYTES Int   -- ^ Size of Modulus n in BYTES
                  , privN    :: Integer     -- ^ Modulus n
                  , privE    :: Integer     -- ^ Exponent e
                  , privD    :: Integer     -- ^ Exponent d
                  , privP    :: Integer     -- ^ p prime number
                  , privQ    :: Integer     -- ^ q prime number
                  , privdP   :: Integer     -- ^ d mod (p-1)
                  , privdQ   :: Integer     -- ^ d mod (q-1)
                  , privQinv :: Integer     -- ^ q^(-1) mod p
                  } deriving (Show, Typeable)


-- | Mask Function
type MGF = Octet -> BYTES Int -> Octet
