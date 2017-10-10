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

         -- ** Stream ciphers.
         -- $streamcipher$
       , StreamCipher, makeCipherI
       , transform, transform'
       -- ** Unsafe encryption and decryption.
       -- $unsafecipher$
       --
       , unsafeEncrypt, unsafeDecrypt, unsafeEncrypt', unsafeDecrypt'

       ) where

import Control.Monad.IO.Class          (liftIO)
import Data.ByteString.Internal as IB
import Foreign.Ptr                     (castPtr)
import Raaz.Core
import Raaz.Core.Util.ByteString as B

-- $cipherdoc$
--
-- Ciphers provide symmetric encryption in the raaz library and are
-- captured by the type class `Cipher`.  They are instances of the
-- class `Symmetric` and the associated type `Key` captures the all
-- that is required to determine the encryption and decryption
-- process. In most ciphers, this includes what is know as the
-- _encryption key_ as well as the _initialisation vector_.
--
-- Instances of `Cipher` is only required to provide full block
-- encryption/decryption algorithms.  Implementations are captured by
-- two types.
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

-- $streamcipher$
--
-- Stream ciphers are special class of ciphers which can encrypt
-- messages of any length (not necessarily multiples of block length).
-- Typically, stream ciphers are obtained by xoring the data with a
-- stream of prg values that the stream ciphers generate. As a
-- consequence, the encryption and decryption is the same algorithm.
-- one can also use the stream cipher as a pseudo-random generator.
--
-- We have the class `StreamCipher` that captures valid stream ciphers.
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
     , cipherStartAlignment :: Alignment
     }

-- | Type constraints on the memory of a block cipher implementation.
type CipherM cipher encMem decMem = ( Initialisable encMem (Key cipher)
                                    , Initialisable decMem (Key cipher)
                                    , Primitive cipher
                                    ) -- TODO: More need initialisable from buffer.

-- | Some implementation of a block cipher. This type is existentially
-- quantifies over the memory used in the implementation.
data SomeCipherI cipher =
  forall encMem decMem . CipherM cipher encMem decMem
  => SomeCipherI (CipherI cipher encMem decMem)


instance BlockAlgorithm (CipherI cipher encMem decMem) where
  bufferStartAlignment = cipherStartAlignment

instance Describable (CipherI cipher encMem decMem) where
  name        = cipherIName
  description = cipherIDescription


instance Describable (SomeCipherI cipher) where
  name         (SomeCipherI cI) = name cI
  description  (SomeCipherI cI) = description cI

instance BlockAlgorithm (SomeCipherI cipher) where
  bufferStartAlignment (SomeCipherI imp) = bufferStartAlignment imp


-- | Class capturing ciphers. The implementation of this class should
-- give an encryption and decryption algorithm for messages of length
-- which is a multiple of the block size.  Needless to say, the
-- encryption and decryption should be inverses of each other for such
-- messages.
class (Primitive cipher, Implementation cipher ~ SomeCipherI cipher, Describable cipher)
      => Cipher cipher

-- | Class that captures stream ciphers. An instance of `StreamCipher`
-- should be an instance of `Cipher`, with the following additional
-- constraints.
--
-- 1. The encryption and decryption should be the same algorithm.
--
-- 2. Encryption/decryption can be applied to a messages of length @l@
--    even if @l@ is not a multiple of block length.
--
-- 3. The encryption of a prefix of a length @l@ of a message @m@
--    should be the same as the @l@ length prefix of the encryption of
--    @m@.
--
-- It is the duty of the implementer of the cipher to ensure that the
-- above conditions are true before declaring an instance of a stream
-- cipher.
class Cipher cipher => StreamCipher cipher


-- | Constructs a `CipherI`  value out of a stream transformation function. Useful in
--   building a Cipher instance of a stream cipher.
makeCipherI :: String                                -- ^ name
            -> String                                -- ^ description
            -> (Pointer -> BLOCKS prim -> MT mem ()) -- ^ stream transformer
            -> Alignment                             -- ^ buffer starting alignment
            -> CipherI prim mem mem
makeCipherI nm des trans = CipherI nm des trans trans

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
               => c                -- ^ The cipher
               -> Implementation c -- ^ The implementation to use
               -> Key c            -- ^ The key to use
               -> ByteString       -- ^ The string to encrypt.
               -> ByteString
unsafeEncrypt' c someImpl@(SomeCipherI impl) =
  unsafeCipherAction c someImpl (encryptBlocks impl)

-- | Decrypts the given `ByteString`. This function is unsafe because
-- it only works correctly when the input `ByteString` is of length
-- which is a multiple of the block length of the cipher.
unsafeDecrypt' :: Cipher c
               => c                -- ^ The cipher
               -> Implementation c -- ^ The implementation to use
               -> Key c            -- ^ The key to use
               -> ByteString       -- ^ The string to encrypt.
               -> ByteString
unsafeDecrypt' c someImpl@(SomeCipherI impl) key bs =
  unsafeCipherAction c someImpl (decryptBlocks impl) key bs

unsafeCipherAction :: (Cipher c, Initialisable someMem (Key c))
                   => c
                   -> Implementation c
                   -> (Pointer -> BLOCKS c -> MT someMem ())
                   -> Key c
                   -> ByteString
                   -> ByteString

unsafeCipherAction c impl act key bs = IB.unsafeCreate sbytes go
  where strSz           = B.length bs
        -- | Buffer size is at least the size of the input.
        bufSz           = atLeast strSz `asTypeOf` blocksOf 1 (pure c)
        -- | Where the action happens.
        go    ptr       = allocBufferFor impl bufSz $ \ buf -> insecurely $ do
          -- | Copy the input string to the buffer.
          liftIO $ unsafeCopyToPointer bs buf -- Copy the input to buffer.
          initialise key
          act buf bufSz
          -- Copy the data in the buffer back to the destination pointer.
          liftIO $ Raaz.Core.memcpy (destination (castPtr ptr)) (source buf) strSz

        -- | Needed by unsafeCreate
        BYTES sbytes    = inBytes strSz

-- | Transforms a given bytestring using a stream cipher. We use the
-- transform instead of encrypt/decrypt because for stream ciphers
-- these operations are same.

transform' :: StreamCipher c
           => c
           -> Implementation c
           -> Key c
           -> ByteString
           -> ByteString
transform' = unsafeEncrypt'

-- | Transform a given bytestring using the recommended implementation
-- of a stream cipher.
transform :: (StreamCipher c, Recommendation c)
           => c
           -> Key c
           -> ByteString
           -> ByteString
transform c = transform' c $ recommended $ pure c



-- | Encrypt using the recommended implementation. This function is
-- unsafe because it only works correctly when the input `ByteString`
-- is of length which is a multiple of the block length of the cipher.
unsafeEncrypt :: (Cipher c, Recommendation c)
              => c            -- ^ The cipher
              -> Key c        -- ^ The key to use
              -> ByteString   -- ^ The string to encrypt
              -> ByteString
unsafeEncrypt c = unsafeEncrypt' c $ recommended $ pure c


-- | Decrypt using the recommended implementation. This function is
-- unsafe because it only works correctly when the input `ByteString`
-- is of length which is a multiple of the block length of the cipher.
unsafeDecrypt :: (Cipher c, Recommendation c)
              => c            -- ^ The cipher
              -> Key c        -- ^ The key to use
              -> ByteString   -- ^ The string to encrypt
              -> ByteString
unsafeDecrypt c = unsafeDecrypt' c $ recommended $ pure c
