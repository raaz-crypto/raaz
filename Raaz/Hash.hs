{-|

This module exposes all the cryptographic hash functions available
under the raaz library.

-}
{-# OPTIONS_GHC -fno-warn-warnings-deprecations #-}

module Raaz.Hash
       (
         -- * Cryptographic hashes and hmacs.
         -- $computingHash$

         -- ** Encoding and displaying.
         -- $encoding$
         --
         Hash, hash, hashFile, hashSource
       , HMAC, hmac, hmacFile, hmacSource
         -- * Exposing individual hashes.
         -- $individualHashes$

       , module Raaz.Hash.Sha224
       , module Raaz.Hash.Sha256
       , module Raaz.Hash.Sha384
       , module Raaz.Hash.Sha512
       -- , module Raaz.Hash.Blake256

       ) where

-- import Raaz.Hash.Blake256
import Raaz.Hash.Sha224
import Raaz.Hash.Sha256
import Raaz.Hash.Sha384
import Raaz.Hash.Sha512

import Raaz.Hash.Internal      ( Hash, hash, hashFile, hashSource )
import Raaz.Hash.Internal.HMAC ( HMAC, hmac, hmacFile, hmacSource )

-- $computingHash$
--
-- === NOTE: SHA1 is broken.
--
-- SHA1 is no more available form this module, its use is highly
-- depreciated. If you want to use it for transition please import
-- Raaz.Hash.Sha1 specifically

-- The cryptographic hashes provided by raaz give the following
-- guarantees:
--
-- 1. Distinct hashes are distinct types and hence it is a compiler
--    error to compare two different hashes.
--
-- 2. A hash and its associated hmac are distinct types and hence
--    it is an compile time error to compare a hash with its  hmac.
--
-- 3. The `Eq` instance for hashes and the corresponding hmacs use
--    a constant time equality test and hence it is safe to check
--    equality using the operator `==`.
--
-- The functions `hash`, `hashFile`, and `hashSource` provide a rather
-- high level interface for computing hashes. For hmacs the associated
-- functions are `hmac`, `hmacFile`, and `hmacSource`

-- $encoding$
--
-- When interfacing with other applications or when printing output to
-- users, it is often necessary to encode hash, hmac or their keys as
-- strings. Applications usually present hashes encoded in base16. The
-- `Show` and `Data.String.IsString` instances for the hashes exposed
-- here follow this convention.
--
-- More generaly, hashes, hmacs and their key are instances of type
-- class `Raaz.Core.Encode.Encodable` and can hence can be encoded in
-- any of the formats supported in raaz.

-- $individualHashes$
--
-- Individual hash and hmacs are exposed via their respective modules.
-- These module also export the specialized variants for `hashSource`,
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

{-# ANN module "HLint: ignore Use import/export shortcut" #-}
