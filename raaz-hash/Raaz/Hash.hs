{-|

This module exposes all the cryptographic hash functions available
under the raaz library. You can also import the module for the
individual hash function for example "Raaz.Hash.Sha1" for the `SHA1`.
Each of the hash types are to be treated as opaque types as their
constructors are not exposed from this module. This is to take
advantage of the type checking. However, if you want to get the
constructor for the hash type say `SHA1`, you could import the module
"Raaz.Hash.Sha1.Type".

-}

module Raaz.Hash
       (
         -- * Computing cryptographic hashes.
         -- $computingHash$
         --
         module Raaz.Hash.Sha1
       , module Raaz.Hash.Sha224
       , module Raaz.Hash.Sha256
       , module Raaz.Hash.Sha384
       , module Raaz.Hash.Sha512
       , sourceHash, hash, hashFile
       , toHex, toByteString
       ) where


import Raaz.Hash.Sha1
import Raaz.Hash.Sha224
import Raaz.Hash.Sha256
import Raaz.Hash.Sha384
import Raaz.Hash.Sha512
import Raaz.Primitives.Hash ( sourceHash, hash, hashFile )
import Raaz.Types           ( toByteString               )
import Raaz.Util.ByteString ( toHex                      )

-- $computingHash$
--
-- As opposed to other cryptographic libraries, we capture each
-- cryptographic hash by a separate type. These types are instances of
-- the type class `Raaz.Primitives.Hash.Hash`. A user should treat
-- them as opaque types for better type safety. In case one wants
-- binary or hexadecimal encoding the functions `toByteString` and
-- `toHex` can be used respectively.
--
-- There are three functions that you may use to compute the
-- cryptographic hash. The most generic function for computing a
-- cryptographic hash is `sourceHash`. The input to this function is
-- any instance of the class `Raaz.ByteSource.ByteSource` which
-- includes file `System.IO.Handle`, strict as well as lazy
-- bytestrings and others. The result type is wrapped in an `IO` monad
-- as reading data from certain byte sources like handle can have side
-- effect.
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
-- This module also export the specialised variants for `sourceHash`,
-- `hash` and `hashFile` for specific hashes.  For example, in the
-- case of `SHA1` these functions are called `sourceSha1`, `sha1` and
-- `sha1File` respectively. This is useful in contexts where the type
-- of the hash cannot be infered from the contexts.
--
-- > sha1Checksum :: FilePath -> IO ByteString
-- >            -- compute the  sha1 checksum
-- > sha1DChecksum = sha1File fp >=> return . toHex
