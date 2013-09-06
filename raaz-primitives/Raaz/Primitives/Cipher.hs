{-

A cryptographic cipher abstraction.

-}

{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE DataKinds             #-}

module Raaz.Primitives.Cipher
       ( CipherGadget(..)
       , Mode(..)
       , Stage(..)
       , unsafeApply
       ) where

import qualified Data.ByteString.Lazy     as L
import           Data.ByteString.Internal
import           Prelude                  hiding (length)
import           System.IO.Unsafe         (unsafePerformIO)
import           Foreign.Marshal.Alloc    (allocaBytes)
import           Foreign.Ptr

import           Raaz.ByteSource
import           Raaz.Memory
import           Raaz.Primitives
import           Raaz.Util.ByteString

-- | Block Ciphers can work in a number of modes which is captured by
-- this datatype
data Mode = ECB   -- ^ Electronic codebook
          | CBC   -- ^ Cipher-block chaining
          | CTR   -- ^ Counter

-- | Ciphers work in two stages
-- * Encryption
-- * Decryption
data Stage = Encryption | Decryption

-- | This class captures encryption and decryption by a Cipher.
class ( Gadget (g Encryption)
      , Gadget (g Decryption)
      , HasPadding    (PrimitiveOf (g Encryption))
      , Initializable (PrimitiveOf (g Encryption))
      , (PrimitiveOf (g Encryption)) ~ (PrimitiveOf (g Decryption))
      ) => CipherGadget g where
  -- | Given a gadget to perform the encryption this can be used to
  -- encrypt a bytesource. This initializes gadget everytime you use
  -- this so this is not the best thing you would want to do if you are
  -- encrypting several sources.
  encrypt :: ( PureByteSource src )
          => g Encryption    -- ^ Gadget Type to Use
          -> ByteString      -- ^ Key
          -> src             -- ^ Source
          -> L.ByteString    -- ^ Encrypted Source
  encrypt g k src = unsafePerformIO $ applyBS g k src
  {-# NOINLINE encrypt #-}

  -- | Given a gadget and the encrypted source it gives you the
  -- decrypted data.
  decrypt :: ( PureByteSource src )
          => g Decryption    -- ^ Gadget Type to Use
          -> ByteString      -- ^ Key
          -> src             -- ^ Source
          -> L.ByteString -- ^ Encrypted Source
  decrypt g k src = unsafePerformIO $ applyBS g k src
  {-# NOINLINE decrypt #-}

applyBS :: ( Gadget g
         , HasPadding (PrimitiveOf g)
         , Initializable (PrimitiveOf g)
         , PureByteSource src
         )
      => g               -- ^ Gadget Type to Use
      -> ByteString      -- ^ Key
      -> src             -- ^ Source
      -> IO L.ByteString -- ^ Encrypted Source
applyBS g key src = do
   ng <- createGadget g
   initialize ng (getIV key)
   transformUnsafeGadget ng src
     where
       createGadget :: Gadget g => g -> IO g
       createGadget _ = newGadget =<< newMemory
{-# INLINE applyBS #-}

-- | Encrypts/Decrypts a bytestring using the given gadget. It only
-- encrypts in multiple of BlockSize, so user must ensure that.
unsafeApply   :: (Gadget g, Initializable (PrimitiveOf g))
              => g                       -- ^ Gadget
              -> ByteString              -- ^ Key
              -> ByteString              -- ^ Plain data
              -> BLOCKS (PrimitiveOf g)  -- ^ Number of Blocks to encrypt
              -> ByteString              -- ^ Encrypted data
unsafeApply g key plain n = unsafePerformIO $ allocaBytes nsize with
  where
    getPrim :: Gadget g => g -> PrimitiveOf g
    getPrim _ = undefined
    nbytes = fromIntegral n * blockSize (getPrim g)
    nsize = fromIntegral nbytes
    with cptr = do
        unsafeNCopyToCryptoPtr nbytes plain cptr
        ng <- createGadget g
        initialize ng (getIV key)
        apply ng n cptr
        _ <- finalize ng
        create nsize copyTo
      where
        copyTo ptr = memcpy ptr (castPtr cptr) nsize
        createGadget :: Gadget g => g -> IO g
        createGadget _ = newGadget =<< newMemory
