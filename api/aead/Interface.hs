{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE DataKinds                  #-}
-- | The interface for an aead construction using a stream cipher like
-- chacha20 and authenticator like poly1305.
module Interface( -- * Locking and unlocking stuff
                  Locked, lock, unlock
                  -- ** Additional data.
                , AEAD, unsafeToCipherText, unsafeToAuthTag, unsafeAEAD
                , lockWith, unlockWith
                , AEADMem, Cipher, Auth
                ) where

import           Data.ByteString
import           System.IO.Unsafe ( unsafePerformIO )

import           Raaz.Core
import           Control.Monad.Reader
import qualified Cipher.Implementation as CI
import qualified Auth.Implementation   as AI

import qualified Cipher.Utils as CU
import qualified Auth.Utils as AU

import qualified Cipher.Buffer as CB


type Cipher = CI.Prim
type Auth   = AI.Prim

data AEAD plain aad = AEAD { unsafeToAuthTag     :: Auth
                           , unsafeToCipherText  :: ByteString
                           }

-- | Create an AEAD packet from the underlying authentication tag and
-- cipher text.
unsafeAEAD :: Auth        -- ^ the authentication tag
           -> ByteString  -- ^ the cipher text
           -> AEAD plain aad
unsafeAEAD = AEAD


type Locked plain   = AEAD plain ()

data AEADMem = AEADMem { cipherInternals :: CI.Internals
                       , authInternals   :: AI.Internals
                       , internBuffer    :: CB.Buffer 1
                       }

instance Memory AEADMem where
  memoryAlloc     = AEADMem <$> memoryAlloc <*> memoryAlloc <*> memoryAlloc
  unsafeToPointer = unsafeToPointer . cipherInternals

instance Initialisable AEADMem (Key Cipher, Nounce Cipher) where
  initialise (k, n) = do
    -- setup and return the internal buffer
    -- and return for generating the keystream.
    buf <- withReaderT internBuffer $ do
      CB.clearBuffer
      ask
    -- Generate the keystream for initialising the auth internals
    -- into the buffer.
    withReaderT cipherInternals $
      let prxy :: Proxy Cipher
          prxy = Proxy
      in do initialise k
            initialise n
            initialise (0 `blocksOf` prxy)
            CU.processBuffer buf

    -- Initialise the authenticator internals from the buffer
    withReaderT authInternals $ do
      aI <- ask
      unsafeTransfer (initialiser aI) $ forgetAlignment $ CB.getBufferPointer buf

--------------------- Internal functions ---------------------------------
---
-- These are some of the internal functions that are used by various
-- lock unlock functions. One of the constraints that we want to
-- enforce is that unauthenticated input should never be
-- decrypted. Hence, despite their cute names, these functions should
-- not be exposed to the user from this module


-- | Transform the input bytestring with the cipher.
transform :: ByteString -- The plain text associated with the data
          -> MT AEADMem ByteString
transform = withReaderT cipherInternals . CU.transform

-- | Compute the authenticator
computeAuth :: Encodable aad
            => aad               -- ^ The additional data that needs
                                 -- to be authenticated
            -> ByteString        -- ^ The cipher text.
            -> MT AEADMem Auth
computeAuth aad cText  = withReaderT authInternals $
  let (aadWr, lAAD) = padAndLen aad
      (cWr, lC)     = padAndLen cText
      authWr        = aadWr <> cWr <> write lAAD <> write lC
    in AU.processByteSource (toByteString authWr) >> extract

verify :: Encodable aad
       => aad
       -> AEAD plain aad
       -> MT AEADMem Bool
verify aad aead = (==) (unsafeToAuthTag aead) <$> computeAuth aad (unsafeToCipherText aead)

-- | Encrypt a plain text object.
encrypt :: Encodable plain
        => plain      -- The plain object that needs encryption
        -> MT AEADMem ByteString
encrypt = transform . toByteString


-- | Decrypt to recover the plain text object. We assume a stream
-- cipher and hence transform is the encryption and decryption
-- routine.
decrypt :: Encodable plain
        => AEAD plain tag
        -> MT AEADMem (Maybe plain)
decrypt = fmap fromByteString . transform . unsafeToCipherText

-- | Compute the padded write of an encodable element and its length.
padAndLen :: Encodable a => a -> (WriteIO, LE Word64)
padAndLen a = (padWrite 0 pL aWr, len)
  where aWr   = writeEncodable a
        len   = toLen (transferSize aWr)
        toLen = toEnum . fromEnum
        pL    = 1 `blocksOf` (Proxy :: Proxy Auth)

-- | This function takes the plain text and the additional data, and
-- constructs the AEAD token. A peer who has the right @(key, nounce)@
-- pair and the `aad` can recover the unencrypted object using teh
-- `unlockWith` function.
lockWith :: (Encodable plain, Encodable aad)
        => aad              -- ^ the authenticated additional data.
        -> Key Cipher       -- ^ The key for the stream cipher
        -> Nounce Cipher    -- ^ The nounce used by the stream cipher.
        -> plain            -- ^ the unencrypted object
        -> AEAD plain aad
lockWith aad k n plain = unsafePerformIO $ insecurely $ do
  initialise (k,n)
  cText <- encrypt plain
  flip AEAD cText <$> computeAuth aad cText

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
           -> Nounce Cipher    -- ^ The nounce used by the stream cipher.
           -> AEAD plain aad   -- ^ The encrypted authenticated version of the data.
           -> Maybe plain
unlockWith aad k n aead = unsafePerformIO $ insecurely $ do
  initialise (k,n)
  isSuccess <- verify aad aead
  if isSuccess then decrypt aead else return Nothing


-- | Generate a locked version of an unencrypted object. You will need
-- the exact same key and nounce to unlock the object.
lock :: Encodable plain
     => Key Cipher
     -> Nounce Cipher
     -> plain
     -> Locked plain
lock = lockWith ()


-- | Unlock the
unlock :: Encodable plain
       => Key Cipher
       -> Nounce Cipher
       -> Locked plain
       -> Maybe plain
unlock = unlockWith ()
