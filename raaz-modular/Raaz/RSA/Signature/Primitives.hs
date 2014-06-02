{-# LANGUAGE TypeFamilies #-}
module Raaz.RSA.Signature.Primitives
       ( rsaPKCSSign
       , rsaPKCSVerify
       ) where

import           Control.Exception        ( throw )
import           Foreign.Storable
import qualified Data.ByteString           as BS

import           Raaz.Core.Types
import qualified Raaz.Core.Util.ByteString as BU

import           Raaz.Public
import           Raaz.RSA.Exception
import           Raaz.RSA.Types
import           Raaz.Number.Internals
import           Raaz.Number

-- | RSA signature generation primitive
rsasp1 :: ( Num w
          , Modular w
          , Eq w
          , Ord w
          )
       => PrivateKey w
       -> w
       -> w
rsasp1 privK m | (m < 0) || (m >= n) =
                  throw MessageRepresentativeOutOfRange
               | otherwise = powModuloSafe m d n
  where
    n = privN privK
    d = privD privK

-- | RSA signature verification primitive
rsavp1 :: ( Num w
          , Modular w
          , Eq w
          , Ord w
          )
       => PublicKey w
       -> w
       -> w
rsavp1 (PublicKey n e) s
  | (s < 0) || (s >= n) = throw SignatureRepresentativeOutOfRange
  | otherwise = powModulo s e n


-- Note: Doesn't handle the case when message is larger than the data
-- hash function can handle. It is intended to output message to long
-- error.

-- | EMSA-PKCS1-v1_5 deterministic encoding routine
emsaPKCSEncode :: ( DEREncoding h
                  , Modular w
                  , Storable w
                  , Num w
                  , Eq w
                  , Ord w
                  )
               => h  -- ^ Hashed Message
               -> w  -- ^ Encoded Message
emsaPKCSEncode m = em
 where
   -- Step 1 and 2
   emLen = BYTES $ sizeOf em
   t = derEncode m
   tLen = BU.length t
   -- Step 4
   psLen = emLen - tLen - 3
   bps = BS.replicate (fromIntegral psLen) 0xff
   -- Step 5
   em = os2wp $ BS.concat [ BS.singleton 0x00
                          , BS.singleton 0x01
                          , bps
                          , BS.singleton 0x00
                          , t]

-- | RSASSA-PKCS1-v1_5 Signature generature routine.
rsaPKCSSign :: ( DEREncoding h
               , Num w
               , Modular w
               , Storable w
               , Eq w
               , Ord w
               )
            => h            -- ^ Hashed Message
            -> PrivateKey w -- ^ Private Key
            -> w            -- ^ Signature
rsaPKCSSign m privK = rsasp1 privK $ emsaPKCSEncode m

-- | RSASSA-PKCS1-v1_5 Signature verification routine.
rsaPKCSVerify :: ( DEREncoding h
                 , Num w
                 , Modular w
                 , Storable w
                 , Eq w
                 , Ord w
                 )
              => h             -- ^ Hashed Message
              -> PublicKey w   -- ^ Private Key
              -> w             -- ^ Signature to be verified
              -> Bool          -- ^ valid (True) or Invalid (False)
rsaPKCSVerify m pubK sig = rsavp1 pubK sig == emsaPKCSEncode m
