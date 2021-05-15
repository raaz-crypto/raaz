{-# LANGUAGE FlexibleContexts #-}

-- | The interface for a stream cipher. For stream ciphers, both
-- encrypt and decrypt are same. One of the advantage of stream cipher
-- is that it allows rewinding/advancing the stream before encrypting
-- and decryption. This interface also supports such
-- rewinding/advancing.
module Interface( Cipher
                , encrypt
                , decrypt
                , encryptAt
                , decryptAt
                , name
                , description
                ) where

import           Data.ByteString
import           System.IO.Unsafe ( unsafePerformIO )

import           Raaz.Core
import           Implementation

import qualified Utils as U

type Cipher = Implementation.Prim

-- | Encrypt using the cipher.
encrypt :: Key Prim     -- ^ The key for the stream cipher
        -> Nounce Prim  -- ^ The nounce used by the stream cipher.
        -> ByteString   -- ^ The bytestring to process
        -> ByteString
encrypt key nounce = encryptAt key nounce mempty

-- | Same as encrypt but first advances so many blocks.
encryptAt :: Key Prim
          -> Nounce Prim
          -> BlockCount Prim
          -> ByteString
          -> ByteString
encryptAt key nounce blk bs = unsafePerformIO $ withMemory $ \ mem -> do
  initialise key mem
  initialise nounce mem
  initialise blk mem
  U.transform bs mem

-- | Same as decrypt but first advance so many blocks.
decryptAt :: Key Prim
          -> Nounce Prim
          -> BlockCount Prim
          -> ByteString
          -> ByteString
decryptAt = encryptAt

-- | Decrypt using the cipher. Since we are concerned with stream
-- ciphers both encrypt and decrypt are the same.
decrypt :: Key Prim
        -> Nounce Prim
        -> ByteString
        -> ByteString
decrypt = encrypt
