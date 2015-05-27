{-|

This module exposes all the cryptographic hash functions available
under the raaz library.

-}

module Raaz.Hash
       (
         -- * Computing cryptographic hashes.
         -- $computingHash$
         --
         sourceHash, hash, hashFile
       , toHex, toByteString
         -- * Exposing individual hashes.
         -- $individualHashes$
       , module Raaz.Hash.Sha1
       , module Raaz.Hash.Sha224
       , module Raaz.Hash.Sha256
       -- , module Raaz.Hash.Sha384
       -- , module Raaz.Hash.Sha512
       -- , module Raaz.Hash.Blake256
       ) where

-- import Raaz.Hash.Blake256 hiding ( toByteString, toHex )
import Raaz.Hash.Sha1     hiding ( toByteString, toHex )
import Raaz.Hash.Sha224   hiding ( toByteString, toHex )
import Raaz.Hash.Sha256   hiding ( toByteString, toHex )
-- import Raaz.Hash.Sha384   hiding ( toByteString, toHex )
-- import Raaz.Hash.Sha512   hiding ( toByteString, toHex )

import Raaz.Core.Primitives.Hash ( sourceHash, hash, hashFile )
import Raaz.Core.Types           ( toByteString               )
import Raaz.Core.Util.ByteString ( toHex                      )

-- $computingHash$
--
-- As opposed to other cryptographic libraries, we capture each
-- cryptographic hash by a separate type. These types are instances of
-- the type class `Raaz.Primitives.Hash.Hash`. Each of the hash types
-- are to be treated as /opaque types/ as their constructors are not
-- exposed from this module. This is to take advantage of the type
-- checking. A cryptographic hash is an instances of the class
-- `EndianStore`. Therefore, binary or for that matter hexadecimal
-- encoding can be obtained using the functions `toByteString` and
-- `toHex` respectively without having access to the constructors.
-- There is an internal module for each hash type which exposes the
-- constructors. For example, constructor for the hash `SHA1` is
-- exposed through the module "Raaz.Hash.Sha1.Internal". However, this
-- is meant to be used when the standard interfaces provided by raaz
-- is not sufficient and should be imported in those rare occasions.
--
-- There are three functions that you may use to compute the
-- cryptographic hash. The most generic function for computing a
-- cryptographic hash is `sourceHash`. The input to this function is
-- any instance of the class `Raaz.ByteSource.ByteSource` which
-- includes file `System.IO.Handle`, strict as well as lazy
-- bytestrings. The result type is wrapped in an `IO` monad as reading
-- data from certain byte sources like handle can have side effect.
--
-- > sourceHash :: (Hash hash, ByteSource src) => src -> IO hash
--
-- If the input byte source is an instance of
-- `Raaz.ByteSource.PureByteSource`, like for example strict
-- `Data.ByteString.Bytestring` or lazy
-- `Data.ByteString.Lazy.ByteString` byte strings, one can use the
-- pure function `hash`.
--
-- > hash :: (Hash hash, PureByteSource src) => src -> hash
--
-- Finally there is `hashFile` that computes the hash of a file
--
-- > hashFile :: Hash hash => FilePath -> IO hash
--


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
