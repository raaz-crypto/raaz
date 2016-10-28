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
     }

-- | Type constraints on the memory of a block cipher implementation.
type CipherM cipher encMem decMem = ( Initialisable encMem (Key cipher)
                                    , Initialisable decMem (Key cipher)
                                    ) -- TODO: More need initialisable from buffer.

-- | Some implementation of a block cipher. This type is existentially
-- quantifies over the memory used in the implementation.
data SomeCipherI cipher =
  forall encMem decMem . CipherM cipher encMem decMem
  => SomeCipherI (CipherI cipher encMem decMem)

instance Describable (CipherI cipher encMem decMem) where
  name        = cipherIName
  description = cipherIDescription


instance Describable (SomeCipherI cipher) where
  name         (SomeCipherI cI) = name cI
  description  (SomeCipherI cI) = description cI


-- | Class capturing ciphers. The implementation of this class should
-- give an encryption and decryption algorithm for messages of length
-- which is a multiple of the block size.  Needless to say, the
-- encryption and decryption should be inverses of each other for such
-- messages.
class (Symmetric cipher, Implementation cipher ~ SomeCipherI cipher)
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
makeCipherI :: Primitive prim
            => String                                -- ^ name
            -> String                                -- ^ description
            -> (Pointer -> BLOCKS prim -> MT mem ()) -- ^ stream transformer
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
