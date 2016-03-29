{-# LANGUAGE CPP                       #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE RecordWildCards           #-}
{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE FlexibleInstances         #-}
{-# LANGUAGE MultiParamTypeClasses     #-}
{-# LANGUAGE ScopedTypeVariables       #-}
{-# LANGUAGE ConstraintKinds           #-}

module Raaz.Cipher.Internal
       ( Cipher, CipherMode(..)
       -- * Implementation of ciphers
       , CipherI(..), SomeCipherI(..)
       -- ** Unsafe encryption and decryption.
       -- $unsafecipher$
       , unsafeEncrypt, unsafeDecrypt, unsafeEncrypt', unsafeDecrypt'
       ) where


import Data.ByteString.Internal as IB
import Foreign.Ptr (castPtr)

import Raaz.Core
import Raaz.Core.Util.ByteString as B


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
-- decryption of data. There are multiple ways to handle arbitrary
-- sized strings like padding, cipher block stealing etc. They are not
-- exposed here thought.
--
-- These functions are exposed here for testing and benchmarking and
-- nothing else


-- | Encrypt the given bytestring.
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

-- | Encrypt using the recommended implementation.
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
    $ \ptr -> action (castPtr ptr) len
  where len         = atMost (B.length bs) `asTypeOf` blocksOf 1 c
        BYTES bytes = inBytes len

-- | Decrypts the given bytestring.
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

-- | Decrypt using the recommended implementation.
unsafeDecrypt :: (Cipher c, Recommendation c)
              => c            -- ^ The cipher
              -> Key c        -- ^ The key to use
              -> ByteString   -- ^ The string to encrypt
              -> ByteString
unsafeDecrypt c = unsafeDecrypt' c $ recommended c
