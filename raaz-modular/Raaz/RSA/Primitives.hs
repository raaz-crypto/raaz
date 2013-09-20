{-# LANGUAGE TypeFamilies #-}
module Raaz.RSA.Primitives
       ( mgf1
       , i2osp
       , os2ip
       , rsaesOAEPEncrypt
       , rsaesOAEPEncrypt'
       , rsaesOAEPDecrypt
       , rsaesPKCS1v1_5Encrypt
       , rsaesPKCS1v1_5Encrypt'
       , rsaesPKCS1v1_5Decrypt
       , rsassaPSSSign
       , rsassaPSSSign'
       , rsassaPSSVerify
       , rsassaPKCS1v1_5Sign
       , rsassaPKCS1v1_5Verify
       ) where

import           Control.Exception
import qualified Data.ByteString        as BS
import           Data.List              (foldl')
import           Data.Maybe             (fromMaybe)

import           Raaz.Primitives
import           Raaz.Primitives.Cipher
import           Raaz.Primitives.Hash
import           Raaz.Random
import           Raaz.Types
import qualified Raaz.Util.ByteString   as BU
import           Raaz.Util.Ptr

import           Raaz.Public
import           Raaz.RSA.Exception
import           Raaz.RSA.Types
import           Raaz.Number.Util


-- | Converts non-negative Integer to Octet String
i2osp :: Integer     -- ^ Non Negative Integer
      -> BYTES Int   -- ^ Intended Length of Octet Stream
      -> Octet       -- ^ Octet String of given Length
i2osp x xLen | x >= (256 ^ toInteger xLen) = throw IntegerTooLarge
             | otherwise                   = unsafeI2osp x xLen

unsafeI2osp :: Integer -> BYTES Int -> Octet
unsafeI2osp x xLen = base256 x
  where
    base256 = BS.reverse . fst . BS.unfoldrN (fromIntegral xLen) with
    with b | b <= 0   = Just (0,0)
           | otherwise = Just (fromIntegral $ b `rem` 256, b `div` 256)
{-# INLINE unsafeI2osp #-}


-- | Converts Octet String to non-negative integer
os2ip :: Octet    -- ^ Octet String
      -> Integer  -- ^ Non Negative Integer
os2ip = BS.foldl with 0
  where
    with o w = o * 256 + fromIntegral w
{-# INLINE os2ip #-}

-- | RSA Encryption Primitive
rsaep :: PublicKey  -- ^ Public Key
      -> Integer    -- ^ Message Representative
      -> Integer    -- ^ Ciphertext Representative
rsaep pubK@(PublicKey _ n _) m
  | (m < 0) || (m >= n) = throw MessageRepresentativeOutOfRange
  | otherwise = unsafeRsaep pubK m

unsafeRsaep :: PublicKey -> Integer -> Integer
unsafeRsaep (PublicKey _ n e) m = powModulo m e n
{-# INLINE unsafeRsaep #-}

-- | RSA Decryption Primitive
rsadp :: PrivateKey -- ^ Private Key
      -> Integer    -- ^ Ciphertext Representative
      -> Integer    -- ^ Message Representative
rsadp privK c | (c < 0) || (c >= privN privK) =
                        throw CiphertextRepresentativeOutOfRange
              | otherwise = unsafeRsadp privK c

unsafeRsadp :: PrivateKey -> Integer -> Integer
unsafeRsadp privK c = powModulo c d n
  where
    n = privN privK
    d = privD privK
{-# INLINE unsafeRsadp #-}

-- | RSA signature generation primitive
rsasp1 :: PrivateKey -> Integer -> Integer
rsasp1 privK m | (m < 0) || (m >= n) =
                  throw MessageRepresentativeOutOfRange
               | otherwise = powModulo m d n
  where
    n = privN privK
    d = privD privK

-- | RSA signature verification primitive
rsavp1 :: PublicKey -> Integer -> Integer
rsavp1 (PublicKey _ n e) s
  | (s < 0) || (s >= n) = throw SignatureRepresentativeOutOfRange
  | otherwise = powModulo s e n


--  Note. Label Length still not taken into account for reporting
--  errors as the underlying hash gadget still does not support
--  reoporting maximum size of data it can handle.

-- | OAEP Encryption Routine.
rsaesOAEPEncrypt :: (Gadget g, PaddableGadget g, Hash h, h ~ PrimitiveOf g)
                 => g                -- ^ Hash
                 -> Octet            -- ^ Random hLen bytes
                 -> PublicKey        -- ^ Public Key
                 -> Octet            -- ^ Message
                 -> Maybe Octet      -- ^ Optional Label
                 -> Octet            -- ^ Ciphertext
rsaesOAEPEncrypt h seed pubK bm ml
  | psLen < 0  = throw MessageTooLong
  | otherwise = i2osp (rsaep pubK $ os2ip em) kLen
      where
        psLen = kLen - mLen - (2 * hLen) - 2
        kLen = pubSize pubK
        mLen = BU.length bm
        l = fromMaybe BS.empty ml
        lHash = toByteString $ hash' h l
        hLen = BU.length lHash
        ps = BS.replicate (fromIntegral psLen) 0
        dbLen = kLen - hLen - 1
        db = BS.concat [lHash,ps,BS.singleton 0x01,bm]
        mgf = mgf1 h
        dbMask = mgf seed dbLen
        maskedDB = db `xorOctet` dbMask
        seedMask = mgf maskedDB hLen
        maskedSeed = seed `xorOctet` seedMask
        em = BS.concat [BS.singleton 0x00,maskedSeed,maskedDB]

-- | OAEP Encryption with seed taken from Random Source
rsaesOAEPEncrypt' :: (Gadget g, PaddableGadget g, Hash h, h ~ PrimitiveOf g, StreamGadget src)
                  => g                -- ^ Hash
                  -> RandomSource src -- ^ Random source
                  -> PublicKey        -- ^ Public Key
                  -> Octet            -- ^ Message
                  -> Maybe Octet      -- ^ Optional Label
                  -> IO Octet         -- ^ Ciphertext
rsaesOAEPEncrypt' h rsrc pubK bm ml = do
    seed <- genBytes rsrc $ hashLen h
    return $ rsaesOAEPEncrypt h seed pubK bm ml

-- | OAEP Decryption Routine
rsaesOAEPDecrypt :: (Gadget g, PaddableGadget g, Hash h, h ~ PrimitiveOf g)
                 => g           -- ^ Hash
                 -> PrivateKey  -- ^ Public Key
                 -> Octet       -- ^ Ciphertext
                 -> Maybe Octet -- ^ Optional Label
                 -> Octet       -- ^ Message
rsaesOAEPDecrypt h privK bc ml
  | not decryptOK = throw DecryptionError
  | otherwise = m
 where
   l = fromMaybe BS.empty ml
   mgf = mgf1 h
   kLen = privSize privK
   cLen = BU.length bc
   dbLen = kLen - hLen - 1
   lHash = toByteString $ hash' h l
   hLen = BU.length lHash
   em = i2osp (rsadp privK $ os2ip bc) kLen
   (y,rest) = BS.splitAt 1 em
   (maskedSeed,maskedDB) = BS.splitAt (fromIntegral hLen) rest
   seedMask = mgf maskedDB hLen
   seed = maskedSeed `xorOctet` seedMask
   dbMask = mgf seed dbLen
   db = maskedDB `xorOctet` dbMask
   (lHash', rest') = BS.splitAt (fromIntegral hLen) db
   bone = BS.dropWhile (== 0) rest'
   (o, m) = BS.splitAt 1 bone
  -- Done in this way to avoid timing attacks
   decryptOK = safeAll [ BS.all (== 0x01) o
                       , lHash == lHash'
                       , BS.all (== 0x00) y
                       , cLen == kLen
                       , kLen >= 2*hLen + 2
                       ]


-- | PKCS1 v1_5 Encryption routine. It is not a recommended routine
-- and is provided for compatibily purposes only.
rsaesPKCS1v1_5Encrypt :: Octet          -- ^ Random Bytes of lenght kLen - mLen - 3
                      -> PublicKey      -- ^ Public Key
                      -> Octet          -- ^ Message to be encrypted
                      -> Octet       -- ^ Encrypted ciphertext
rsaesPKCS1v1_5Encrypt seed pubK m
  | mLen > (kLen - 11) = throw MessageTooLong
  | otherwise          = i2osp (rsaep pubK $ os2ip em) kLen
 where
  mLen = BU.length m
  kLen = pubSize pubK
  em = BS.concat [ BS.singleton 0x00
                 , BS.singleton 0x02
                 , seed
                 , BS.singleton 0x00
                 , m]

-- | Encryption routine with the given random source.
rsaesPKCS1v1_5Encrypt' :: StreamGadget g
                       => RandomSource g -- ^ Random Source of Bytes
                       -> PublicKey      -- ^ Public Key
                       -> Octet          -- ^ Message to be encrypted
                       -> IO Octet       -- ^ Encrypted ciphertext
rsaesPKCS1v1_5Encrypt' rsrc pubK m = do
    seed <- genBytesNonZero rsrc seedLen
    return $ rsaesPKCS1v1_5Encrypt seed pubK m
  where
    mLen = BU.length m
    kLen = pubSize pubK
    seedLen = kLen - mLen - 3

-- | PKCS1 v1_5 Decryption routine. It is not a recommended routine
-- and is provided for compatibily purposes only.
rsaesPKCS1v1_5Decrypt :: PrivateKey -- ^ Private Key
                      -> Octet      -- ^ Message to be decrypted
                      -> Octet      -- ^ Decrypted Message
rsaesPKCS1v1_5Decrypt privK c
  | not decryptOk = throw DecryptionError
  | otherwise     = m
 where
  cLen = BU.length c
  kLen = privSize privK
  em = i2osp (rsadp privK $ os2ip c) kLen
  (z,rest1)  = BS.splitAt 1 em
  (t,rest2)  = BS.splitAt 1 rest1
  (ps,rest3) = BS.span (/= 0) rest2
  (z', m)    = BS.splitAt 1 rest3
  -- Done in this way to avoid timing attacks
  decryptOk = safeAll [ BS.all (== 0x00) z
                      , BS.all (== 0x02) t
                      , BS.all (== 0x00) z'
                      , BS.length ps >= 8
                      , kLen >= 11
                      , cLen == kLen]


-- Step 1
-- Note: Not checking length of the message against the maximum data
-- the given hash function can handle.

-- | EMSA-PSS encoding routine. It takes recommended seed length = hLen.
emsaPSSEncode :: (Gadget g, PaddableGadget g, Hash h, h ~ PrimitiveOf g)
              => g
              -> MGF         -- ^ Mask Function
              -> Octet       -- ^ Salt (Random Bytes)
              -> Octet       -- ^ Message to be encoded
              -> BITS Int    -- ^ Maximum bit length of the integer os2ip(encoded message)
              -> Octet       -- ^ Encoded Message
emsaPSSEncode h mgf salt m emBits
  -- Step 3
  | emLen < hLen + sLen + 2 = throw EncodingError
  -- Step 13
  | otherwise               = em
 where
   sLen = BU.length salt
   hLen = BU.length mHash
   (emQuot,emRem) = fromIntegral emBits `quotRem` 8
   psLen = emLen - sLen - hLen - 2
   emLen = BYTES $ if emRem == 0 then emQuot else emQuot + 1
   dbLen = emLen - hLen - 1
   extraBits = cryptoCoerce emLen - emBits
   mHash = toByteString $ hash' h m
   -- Step 5
   m' = BS.concat [ BS.replicate 8 0x00
                  , mHash
                  , salt
                  ]
   -- Step 6
   mh = toByteString $ hash' h m'
   -- Step 7
   bps = BS.replicate (fromIntegral psLen) 0x00
   -- Step 8
   db = BS.concat [ bps
                  , BS.singleton 0x01
                  , salt
                  ]
   -- Step 9
   dbMask = mgf mh dbLen
   -- Step 10
   maskedDB' = db `xorOctet` dbMask
   -- Step 11
   maskedDB = zeroBits extraBits maskedDB'
   -- Step 12
   em = BS.concat [ maskedDB
                  , mh
                  , BS.singleton 0xbc
                  ]

-- | EMSA-PSS verifying routine. It takes recommended seed length = hLen.
emsaPSSVerify :: (Gadget g, PaddableGadget g, Hash h, h ~ PrimitiveOf g)
              => g           -- ^ Hash Gadget
              -> MGF         -- ^ Mask Function
              -> Octet       -- ^ Message to be verified
              -> Octet       -- ^ Encoded Message
              -> BITS Int    -- ^ Maximum bit length of the integer os2ip(encoded message)
              -> Bool        -- ^ Consistent = True OR Inconsistent = False
emsaPSSVerify h mgf m em emBits
  -- Step 3
  |    emLen < hLen + sLen + 2
    || not isLastOK
    || not isMaskedOK
    || not isLeftDBOK
    || not consistent = False
  | otherwise               = True
 where
   mHash = toByteString $ hash' h m
   hLen = BU.length mHash
   sLen = hLen
   psLen = emLen - sLen - hLen - 2
   emLen = BU.length em
   extraBits = cryptoCoerce emLen - emBits
   dbLen = emLen - hLen - 1
   -- Step 4
   isLastOK = BS.last rest2 == 0xbc
   -- Step 5
   (maskedDB,rest1) = BS.splitAt (fromIntegral dbLen) em
   (mh,rest2) = BS.splitAt (fromIntegral hLen) rest1
   -- Step 6
   isMaskedOK = checkZeroBits extraBits maskedDB
   -- Step 7
   dbMask = mgf mh dbLen
   -- Step 8
   db' = maskedDB `xorOctet` dbMask
   -- Step 9
   db = zeroBits extraBits db'
   -- Step 10
   (bpsLenFromDB,rest3) = BS.splitAt (fromIntegral psLen) db
   (one,_) = BS.splitAt 1 rest3
   isLeftDBOK = BS.all (== 0x00) bpsLenFromDB && BS.all (== 0x01) one
   -- Step 11
   bsalt = BS.drop (fromIntegral $ dbLen - sLen)  db
   -- Step 12
   m' = BS.concat [ BS.replicate 8 0x00
                  , mHash
                  , bsalt
                  ]
   mh' = toByteString $ hash' h m'
   -- Step 14 , timing attack resistant comparison
   consistent = BS.all (== 0x00) $ xorOctet mh mh'

-- Note: Doesn't handle the case when message is larger than the data
-- hash function can handle. It is intended to output message to long
-- error.

-- | EMSA-PKCS1-v1_5 deterministic encoding routine
emsaPKCS1v1_5Encode :: DEREncoding h
                    => h           -- ^ Hashed Message
                    -> BYTES Int   -- ^ Intended length of encoded message
                    -> Octet       -- ^ Encoded Message
emsaPKCS1v1_5Encode m emLen
  -- Step 3
  | emLen < tLen + 11 = throw IntendedEncodedMessageLengthTooShort
  -- Step 6
  | otherwise = em
 where
   -- Step 1 and 2
   t = derEncode m
   tLen = BU.length t
   -- Step 4
   psLen = emLen - tLen - 3
   bps = BS.replicate (fromIntegral psLen) 0xff
   -- Step 5
   em = BS.concat [ BS.singleton 0x00
                  , BS.singleton 0x01
                  , bps
                  , BS.singleton 0x00
                  , t]

-- | RSASSA-PSS Signature generating routine
rsassaPSSSign :: (Gadget g, PaddableGadget g, Hash h, h ~ PrimitiveOf g)
              => g                -- ^ Hash
              -> Octet            -- ^ Salt
              -> PrivateKey       -- ^ Private Key
              -> Octet            -- ^ Message to be signed
              -> IO Octet            -- ^ Signature
rsassaPSSSign h salt privK m = return $ i2osp (rsasp1 privK $ os2ip em) kLen
 where
   mgf = mgf1 h
   em = emsaPSSEncode h mgf salt m (modBits - 1)
   kLen = privSize privK
   modBits = numberOfBits $ privN privK
   -- Step 1

rsassaPSSSign' :: (Gadget g, PaddableGadget g, Hash h, h ~ PrimitiveOf g, StreamGadget src)
              => g                -- ^ Hash
              -> RandomSource src -- ^ Random Source
              -> PrivateKey       -- ^ Private Key
              -> Octet            -- ^ Message to be signed
              -> IO Octet         -- ^ Signature
rsassaPSSSign' h rsrc privK m = do
  salt <- genBytes rsrc $ hashLen h
  rsassaPSSSign h salt privK m

-- | RSASSA-PSS Signature verification routine
rsassaPSSVerify :: (Gadget g, PaddableGadget g, Hash h, h ~ PrimitiveOf g)
                => g           -- ^ Hash
                -> PublicKey   -- ^ Public Key
                -> Octet       -- ^ Message
                -> Octet       -- ^ Signature to be verified
                -> IO Bool     -- ^ valid (True) or Invalid (False)
rsassaPSSVerify h pubK m sig
   -- Step 1
   | kLen /= sigLen = return False
   -- Step 4
   | otherwise      = return result `catch` catched
 where
   catched :: RSAException -> IO Bool
   catched _ = return False
   kLen = pubSize pubK
   sigLen = BU.length sig
   modBits = numberOfBits $ pubN pubK
   (mQuot,mRem) = fromIntegral (modBits-1) `quotRem` 8
   emLen = BYTES $ if mRem == 0 then mQuot else mQuot + 1
   -- Step 2
   em = i2osp (rsavp1 pubK $ os2ip sig) emLen
   -- Step 3
   mgf = mgf1 h
   result = emsaPSSVerify h mgf m em (modBits - 1)

-- | RSASSA-PKCS1-v1_5 Signature generature routine.
rsassaPKCS1v1_5Sign :: DEREncoding h
                    => h           -- ^ Hashed Message
                    -> PrivateKey  -- ^ Private Key
                    -> IO Octet    -- ^ Signature
rsassaPKCS1v1_5Sign m privK = return sig
 where
   kLen = privSize privK
   -- Step 1
   em  = emsaPKCS1v1_5Encode m kLen
   -- Step 2
   sig = i2osp (rsasp1 privK $ os2ip em) kLen

-- | RSASSA-PKCS1-v1_5 Signature verification routine.
rsassaPKCS1v1_5Verify :: DEREncoding h
                      => h            -- ^ Hashed Message
                      -> PublicKey    -- ^ Private Key
                      -> Octet        -- ^ Signature to be verified
                      -> IO Bool      -- ^ valid (True) or Invalid (False)
rsassaPKCS1v1_5Verify m pubK sig
   -- Step 1
   | kLen /= sLen  = return False
   -- Step 4
   | otherwise     = return $ em == em'
 where
  kLen = pubSize pubK
  sLen = BU.length sig
  -- Step 2
  em = i2osp (rsavp1 pubK $ os2ip sig) kLen
  -- Step 3
  em' = emsaPKCS1v1_5Encode m kLen

-- | Generates MGF function from the given Hashing Gadget.
mgf1 :: (Gadget g, PaddableGadget g, Hash h, h ~ PrimitiveOf g) => g -> MGF
mgf1 h mgfSeed maskLen
 | maskLen > ((2 ^ (32 :: Int)) * hLen) = throw MaskTooLong
 | otherwise = BS.take (fromIntegral maskLen) $ foldl' with BS.empty [0..n]
 where
  hLen = hashLen h
  (nQ,nR) = quotRem maskLen hLen
  n = if nR == 0 then nQ - 1 else nQ
  with t counter = BS.append t t'
    where
      c = i2osp (fromIntegral counter) 4
      t' = toByteString $ hash' h $ BS.append mgfSeed c

hashLen :: (Hash h,Gadget g, PaddableGadget g, h ~ PrimitiveOf g) => g -> BYTES Int
hashLen = byteSize . primitiveOf
