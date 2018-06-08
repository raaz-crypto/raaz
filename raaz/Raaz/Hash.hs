{-|

This module exposes all the cryptographic hash functions available
under the raaz library.

-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE FlexibleInstances    #-}

module Raaz.Hash
       (
         -- * Cryptographic hashes.
         -- $computingHash$

         -- ** Encoding and displaying.
         -- $encoding$
         --
         Hash, hash, hashFile, hashSource
       , BLAKE2b, BLAKE2s, SHA512, SHA256
         -- * Exposing individual hashes.
         -- $individualHashes$

       ) where


import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import           System.IO
import           System.IO.Unsafe     (unsafePerformIO)


import           Raaz.Core
import           Raaz.Primitive.Blake2.Internal (BLAKE2b, BLAKE2s)
import           Raaz.Primitive.Sha256.Internal (SHA256)
import           Raaz.Primitive.Sha512.Internal (SHA512)
import qualified Raaz.Hash.Blake2b.Util         as Blake2bU
import qualified Raaz.Hash.Blake2s.Util         as Blake2sU
import qualified Raaz.Hash.Sha256.Util          as Sha256U
import qualified Raaz.Hash.Sha512.Util          as Sha512U


-- $computingHash$
--
--
-- The cryptographic hashes provided by raaz give the following
-- guarantees:
--
-- 1. Distinct hashes are distinct types and hence it is a compiler
--    error to compare two different hashes.
--
-- 2. The `Eq` instance for hashes use a constant time equality test
--    and hence it is safe to check equality using the operator `==`.
--
-- The functions `hash`, `hashFile`, and `hashSource` provide a rather
-- high level interface for computing hashes.

-- $encoding$
--
-- When interfacing with other applications or when printing output to
-- users, it is often necessary to encode hash as
-- strings. Applications usually present hashes encoded in base16. The
-- `Show` and `Data.String.IsString` instances for the hashes exposed
-- here follow this convention.
--
-- More generally hashes are instances of type class
-- `Raaz.Core.Encode.Encodable` and can hence can be encoded in any of
-- the formats supported in raaz.

-- $individualHashes$
--
-- Individual hash are exposed via their respective modules.  These
-- module also export the specialized variants for `hashSource`,
-- `hash` and `hashFile` for specific hashes.  For example, if you are
-- interested only in say `SHA512` you can import the module
-- "Raaz.Hash.Sha512". This will expose the functions `sha512Source`,
-- `sha512` and `sha512File` which are specialized variants of
-- `hashSource` `hash` and `hashFile` respectively for the hash
-- `SHA512`. For example, if you want to print the sha512 checksum of
-- a file, you can use the following.
--
-- > sha512Checksum :: FilePath -> IO ()
-- >            -- print the sha512 checksum of a given file.
-- > sha512Checksum fname =  sha512File fname >>= print


-- | The class that captures all cryptographic hashes.
class (Primitive h, Key h ~ (), Digest h ~ h, Equality h, Eq h) => Hash h where
  -- | Computes the cryptographic hash of a given byte source.
  hashSource :: ByteSource src => src -> IO h


-- | Compute the hash of a pure byte source like, `B.ByteString`.
hash :: ( Hash h, PureByteSource src )
     => src  -- ^ Message
     -> h
hash = unsafePerformIO . hashSource
{-# INLINEABLE hash #-}
{-# SPECIALIZE hash :: Hash h => B.ByteString -> h #-}
{-# SPECIALIZE hash :: Hash h => L.ByteString -> h #-}

-- | Compute the hash of file.
hashFile :: Hash h
         => FilePath  -- ^ File to be hashed
         -> IO h
hashFile fileName = withBinaryFile fileName ReadMode hashSource
{-# INLINEABLE hashFile #-}

instance Hash BLAKE2b where
  hashSource = Blake2bU.computeDigest ()

instance Hash BLAKE2s where
  hashSource = Blake2sU.computeDigest ()

instance Hash SHA256 where
  hashSource = Sha256U.computeDigest ()

instance Hash SHA512 where
  hashSource = Sha512U.computeDigest ()
