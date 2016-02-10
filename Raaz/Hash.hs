{-|

This module exposes all the cryptographic hash functions available
under the raaz library.

-}

module Raaz.Hash
       (
         -- * Cryptographic hashes
         -- $computingHash$

         -- ** Encoding hash values
         -- $encoding$
         --
         hash, hashFile, hashSource
         -- ** HMAC computation
       , hmac, hmacFile, hmacSource
         -- * Exposing individual hashes.
         -- $individualHashes$

       -- , module Raaz.Hash.Sha1
       -- , module Raaz.Hash.Sha224
       -- , module Raaz.Hash.Sha256
       -- , module Raaz.Hash.Sha384
       -- , module Raaz.Hash.Sha512
       -- , module Raaz.Hash.Blake256

       ) where

-- import Raaz.Hash.Blake256
-- import Raaz.Hash.Sha1
-- import Raaz.Hash.Sha224
-- import Raaz.Hash.Sha256
-- import Raaz.Hash.Sha384
-- import Raaz.Hash.Sha512

import Raaz.Hash.Internal      ( hash, hashFile, hashSource )
import Raaz.Hash.Internal.HMAC ( hmac, hmacFile, hmacSource )
-- $computingHash$
--
-- As opposed to other cryptographic libraries, we capture each
-- cryptographic hash by a separate type. These types are instances of
-- the type class `Raaz.Hash.Internal.Hash`. Each of the hash types
-- are to be treated as /opaque types/ as their constructors are not
-- exposed from this module. This is to take advantage of the type
-- checking.
--
-- We expose three functions for computing the hash of a message:
-- `hash`, `hashFile` and `sourceHash`.


-- $encoding$
--
-- When interfacing with other applications or when printing output to
-- users, it is often necessary to encode hash values as strings.
-- Applications usually present hashes encoded in base16. The `Show`
-- and `Data.String.IsString` instances for the hashes exposed here
-- follow this convention. For example, you can print the sha1Sum of a
-- file using the following as follows @show . sha1File@.
--
-- More generaly, hashes exposed here are instances of type class
-- `Raaz.Core.Encode.Encodable` and can hence can be encoded in any of
-- the supported formats.

-- $individualHashes$
--
-- Individual hash are exposed via their respective modules.  These
-- module also export the specialized variants for `sourceHash`,
-- `hash` and `hashFile` for specific hashes.  For example, if you are
-- interested only in say `SHA1` you can import the module
-- "Raaz.Hash.Sha1". This will expose the functions `sourceSha1`,
-- `sha1` and `sha1File` which are specialized variants of
-- `sourceHash` `hash` and `hashFile` respectively for the hash
-- `SHA1`. For example, the sha1 checksum can be computed using the
-- following code.
--
-- > sha1Checksum :: FilePath -> IO ByteString
-- >            -- compute the  sha1 checksum
-- > sha1Checksum = fmap toHex . sha1File


{-# ANN module "HLint: ignore Use import/export shortcut" #-}
