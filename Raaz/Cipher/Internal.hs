{-# LANGUAGE CPP                       #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# LANGUAGE ConstraintKinds           #-}

-- | This module exposes the low-level internal details of ciphers. Do
-- not import this module unless you want to implement a new cipher or
-- give a new implementation of an existing cipher.
module Raaz.Cipher.Internal
       (
         -- * Internals of a cipher.
         -- $cipherdoc$
         Cipher, CipherMode(..)
         -- ** Cipher implementation
       , CipherI(..), SomeCipherI(..)
       --
       -- ** Unsafe encryption and decryption.
       -- $unsafecipher$
       --
       , unsafeEncrypt, unsafeDecrypt, unsafeEncrypt', unsafeDecrypt'
       ) where


import Data.ByteString.Internal as IB
import Foreign.Ptr (castPtr)

import Raaz.Core
import Raaz.Core.Util.ByteString as B

-- $cipherdoc$
--
-- Ciphers provide symmetric encryption in the raaz library and are
-- captured by the type class `Cipher`. Instances of `Cipher` are full
-- encryption/decryption algorithms. For a block cipher this means
-- that one also needs to specify the `CipherMode` to make it an
-- instance of the class `Cipher`. They are instances of the class
-- `Symmetric` and the associated type `Key` captures the encryption
-- key for the cipher.
--
-- Implementations of ciphers are captured by two types.
--
-- [`CipherI`:] Values of this type that captures implementations of a
-- cipher.  This type is parameterised over the memory element that is
-- used internally by the implementation.
--
-- [`SomeCipherI`:] The existentially quantified version of `CipherI`
-- over its memory element. By wrapping the memory element inside the
-- existential quantifier, values of this type exposes only the
-- interface and not the internals of the implementation. The
-- `Implementation` associated type of a cipher is the type
-- `SomeCipherI`
--
-- To support a new cipher, a developer needs to:
--
-- 1. Define a new type which captures the cipher. This type should be
--    an instance of the class `Cipher`.
--
-- 2. Define an implementation, i.e. a value of the type `SomeCipherI`.
--
-- 3. Define a recommended implementation, i.e. an instance of the
--    type class `Raaz.Core.Primitives.Recommendation`
--



-- | Block cipher modes.
data CipherMode = CBC -- ^ Cipher-block chaining
                | CTR -- ^ Counter
                deriving (Show, Eq)

-- | The implementation of a block cipher.
data CipherI cipher encMem decMem = CipherI
     { cipherIName         :: String
     , cipherIDescription  :: String
       -- | The underlying block encryption function.
     , encryptBlocks :: Pointer -> BLOCKS cipher -> MT encMem ()
       -- | The underlying block decryption function.
     , decryptBlocks :: Pointer -> BLOCKS cipher -> MT decMem ()
     }

instance Describable (CipherI cipher encMem decMem) where
  name        = cipherIName
  description = cipherIDescription


instance Describable (SomeCipherI cipher) where
  name         (SomeCipherI cI) = name cI
  description  (SomeCipherI cI) = description cI


type CipherM cipher encMem decMem = ( Initialisable encMem (Key cipher)
                                    , Initialisable decMem (Key cipher)
                                    )

-- | Some implementation of a block cipher. This type existentially
-- quantifies over the memory used in the implementation.
data SomeCipherI cipher =
  forall encMem decMem . CipherM cipher encMem decMem
  => SomeCipherI (CipherI cipher encMem decMem)

class (Symmetric cipher, Implementation cipher ~ SomeCipherI cipher)
      => Cipher cipher

------------------ Unsafe cipher operations ------------------------

-- $unsafecipher$
--
-- We expose some unsafe functions to encrypt and decrypt bytestrings.
-- These function works correctly only if the input byte string has a
-- length which is a multiple of the block size of the cipher and
-- hence are unsafe to use as general methods of encryption and
-- decryption of data.  Use these functions for testing and
-- benchmarking and nothing else.
--
-- There are multiple ways to handle arbitrary sized strings like
-- padding, cipher block stealing etc. They are not exposed here
-- though.

-- | Encrypt the given `ByteString`. This function is unsafe because
-- it only works correctly when the input `ByteString` is of length
-- which is a multiple of the block length of the cipher.
unsafeEncrypt' :: Cipher c
               => c                -- ^ The cipher to use
               -> Implementation c -- ^ The implementation to use
               -> Key c            -- ^ The key to use
               -> ByteString       -- ^ The string to encrypt.
               -> ByteString
unsafeEncrypt' c (SomeCipherI imp) key = makeCopyRun c encryptAction
  where encryptAction ptr blks
          = insecurely $ do initialise key
                            encryptBlocks imp ptr blks

-- | Encrypt using the recommended implementation. This function is
-- unsafe because it only works correctly when the input `ByteString`
-- is of length which is a multiple of the block length of the cipher.
unsafeEncrypt :: (Cipher c, Recommendation c)
              => c            -- ^ The cipher
              -> Key c        -- ^ The key to use
              -> ByteString   -- ^ The string to encrypt
              -> ByteString
unsafeEncrypt c = unsafeEncrypt' c $ recommended c

-- | Make a copy and run the given action.
makeCopyRun :: Cipher c
            => c
            -> (Pointer -> BLOCKS c -> IO ())
            -> ByteString
            -> ByteString
makeCopyRun c action bs
  = IB.unsafeCreate bytes
    $ \ptr -> do unsafeNCopyToPointer len bs (castPtr ptr)
                 action (castPtr ptr) len
  where len         = atMost (B.length bs) `asTypeOf` blocksOf 1 c
        BYTES bytes = inBytes len

-- | Decrypts the given `ByteString`. This function is unsafe because
-- it only works correctly when the input `ByteString` is of length
-- which is a multiple of the block length of the cipher.
unsafeDecrypt' :: Cipher c
               => c                -- ^ The cipher to use
               -> Implementation c -- ^ The implementation to use
               -> Key c            -- ^ The key to use
               -> ByteString       -- ^ The string to encrypt.
               -> ByteString
unsafeDecrypt' c (SomeCipherI imp) key = makeCopyRun c decryptAction
  where decryptAction ptr blks
          = insecurely $ do initialise key
                            decryptBlocks imp ptr blks

-- | Decrypt using the recommended implementation. This function is
-- unsafe because it only works correctly when the input `ByteString`
-- is of length which is a multiple of the block length of the cipher.
unsafeDecrypt :: (Cipher c, Recommendation c)
              => c            -- ^ The cipher
              -> Key c        -- ^ The key to use
              -> ByteString   -- ^ The string to encrypt
              -> ByteString
unsafeDecrypt c = unsafeDecrypt' c $ recommended c
