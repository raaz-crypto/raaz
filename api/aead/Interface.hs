{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE RecordWildCards            #-}

-- |
--
-- Module      : aead-api: Interface
-- Description : Generic interface to authenticated encryption.
-- Copyright   : (c) Piyush P Kurur, 2019
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
-- | The interface for an aead construction using a stream cipher like
-- chacha20 and authenticator like poly1305.
module Interface( -- * Locking and unlocking stuff
                  Locked, unsafeLock, unlock
                  -- ** Additional data.
                , AEAD, AuthTag, Cipher
                , unsafeToNounce, unsafeToCipherText, unsafeToAuthTag, unsafeAEAD
                , unsafeLockWith, unlockWith
                , AEADMem
                ) where

import           Data.ByteString
import           System.IO.Unsafe ( unsafePerformIO )

import           Raaz.Core
import qualified Cipher.Implementation as CI
import qualified Auth.Implementation   as AI

import qualified Cipher.Utils as CU
import qualified Auth.Utils as AU

import qualified Cipher.Buffer as CB

-- | The cipher associated with the AEAD computation.
type Cipher = CI.Prim

-- | The message authenticator used with the AEAD computation.
type AuthTag = AI.Prim

-- | This function takes the plain text and the additional data, and
-- constructs the AEAD token. A peer who has the right @(key, nounce)@
-- pair and the `aad` can recover the unencrypted object using the
-- `unlockWith` function.
unsafeLockWith :: (Encodable plain, Encodable aad)
               => aad              -- ^ the authenticated additional data.
               -> Key Cipher       -- ^ The key for the stream cipher
               -> Nounce Cipher    -- ^ The nounce used by the stream cipher.
               -> plain            -- ^ the unencrypted object
               -> AEAD plain aad
unsafeLockWith aad k n plain = unsafePerformIO $ withMemory $ \ mem -> do
  initialise k mem
  initialise n mem
  cText <- encrypt plain mem
  AEAD n cText <$> computeAuth aad cText mem

-- | Unlock an encrypted authenticated version of the data given the
-- additional data, key, and nounce. An attempt to unlock the element
-- can result in `Nothing` if either of the following is true.
--
-- 1. The key, nounce pair used to encrypt the data is incorrect
-- 2. The Authenticated additional data (@aad@) is incorrect
-- 3. The AEAD is of the wrong type and hence the fromByteString failed
-- 4. The AEAD value has been tampered with by the adversery
--
-- The interface provided above makes it impossible to know which of
-- the above three error has happened. This is a deliberate design as
-- revealing the nature of the failure can leak information to a potential
-- attacker.
--
unlockWith :: (Encodable plain, Encodable aad)
            => aad              -- ^ the authenticated additional data.
            -> Key Cipher       -- ^ The key for the stream cipher
            -> AEAD plain aad   -- ^ The encrypted authenticated version of the data.
            -> Maybe plain
unlockWith aad k aead = unsafePerformIO $ withMemory $ \ mem -> do
  initialise k mem
  initialise (unsafeToNounce aead) mem
  isSuccess <- verify aad aead mem
  if isSuccess then decrypt aead mem else return Nothing


-- | Generate a locked version of an unencrypted object. You will need
-- the exact same key and nounce to unlock the object.
unsafeLock :: Encodable plain
           => Key Cipher
           -> Nounce Cipher
           -> plain
           -> Locked plain
unsafeLock = unsafeLockWith ()


-- | Unlock the encrypted packet.
unlock :: Encodable plain
       => Key Cipher
       -> Locked plain
       -> Maybe plain
unlock = unlockWith ()

-- | The locked package containing a payload of type @plain@.
type Locked plain   = AEAD plain ()

-- | An authenticated encrypted packet containing a payload of type
-- @plain@ and additional authenticated data of type @aad@.
data AEAD plain aad = AEAD
  { unsafeToNounce      :: Nounce Cipher
                        -- ^ The nounce use to compute this packet.
  , unsafeToCipherText  :: ByteString
                        -- ^ The associated cipher text.
  , unsafeToAuthTag     :: AuthTag
                        -- ^ The associated authentication tag.
  }

-- | Create an AEAD packet from the underlying authentication tag and
-- cipher text.
unsafeAEAD :: Nounce Cipher
           -> ByteString
           -> AuthTag        -- ^ the authentication tag
           -> AEAD plain aad
unsafeAEAD = AEAD


-- | The internal memory used for computing the AEAD packet. When using
-- this memory for packet computation, it is important to initalise the
-- memory in the following order.
--
-- 1. Initialise with key either using the `initialise` function or, by using
--    the `WriteAccessible` instance using the `mem.
-- 2. Initialise the nounce
--
-- We are then all set to go.
--
data AEADMem = AEADMem { cipherInternals :: CI.Internals
                       , authInternals   :: AI.Internals
                       , internBuffer    :: CB.Buffer 1
                       }

instance Memory AEADMem where
  memoryAlloc     = AEADMem <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . cipherInternals

-- | Initialise with the key of the cipher.
instance Initialisable AEADMem (Key Cipher) where
  initialise k = initialise k . cipherInternals

instance WriteAccessible AEADMem where
  writeAccess = writeAccess . cipherInternals
  afterWriteAdjustment = afterWriteAdjustment . cipherInternals

-- | Initialise after the key is already initialised.
instance Initialisable AEADMem (Nounce Cipher) where
  initialise n AEADMem{..} = do
    initialise n cipherInternals
    let zeroCount = 0 `blocksOf` (Proxy :: Proxy Cipher)
      in initialise zeroCount cipherInternals

    --
    -- Generate the key stream
    --
    CB.memsetBuffer 0 internBuffer                -- clear the internal buffer
    CU.processBuffer internBuffer cipherInternals -- generate the keystream
    --
    -- Initialise the authenticator from the keystream.
    --
    memTransfer (destination authInternals) (source internBuffer)

--------------------- Internal functions ---------------------------------
---
-- These are some of the internal functions that are used by various
-- lock unlock functions. One of the constraints that we want to
-- enforce is that unauthenticated input should never be
-- decrypted. Hence, despite their cute names, these functions should
-- not be exposed to the user from this module

-- | Transform the input bytestring with the cipher.
transform :: ByteString -- The plain text associated with the data
          -> AEADMem
          -> IO ByteString
transform bs = CU.transform bs . cipherInternals

-- | Compute the authenticator
computeAuth :: Encodable aad
            => aad               -- ^ The additional data that needs
                                 -- to be authenticated
            -> ByteString        -- ^ The cipher text.
            -> AEADMem
            -> IO AuthTag
computeAuth aad cText aeadmem =
  AU.processByteSource (toByteString authWr) authMem >> extract authMem
  where (aadWr, lAAD) = padAndLen aad
        (cWr, lC)     = padAndLen cText
        authWr        = aadWr <> cWr <> write lAAD <> write lC
        authMem       = authInternals aeadmem


verify :: Encodable aad
       => aad
       -> AEAD plain aad
       -> AEADMem
       -> IO Bool
verify aad aead = fmap matchTag . computeAuth aad (unsafeToCipherText aead)
  where matchTag = (==) (unsafeToAuthTag aead)

-- | Encrypt a plain text object.
encrypt :: Encodable plain
        => plain      -- The plain object that needs encryption
        -> AEADMem
        -> IO ByteString
encrypt plain = transform $ toByteString plain


-- | Decrypt to recover the plain text object. We assume a stream
-- cipher and hence transform is the encryption and decryption
-- routine.
decrypt :: Encodable plain
        => AEAD plain tag
        -> AEADMem
        -> IO (Maybe plain)
decrypt aead = fmap fromByteString . transform (unsafeToCipherText aead)

-- | Compute the padded write of an encodable element and its length.
padAndLen :: Encodable a => a -> (WriteTo, LE Word64)
padAndLen a = (padWrite 0 pL aWr, len)
  where aWr   = writeEncodable a
        len   = toLen (transferSize aWr)
        toLen = toEnum . fromEnum
        pL    = 1 `blocksOf` (Proxy :: Proxy AuthTag)
