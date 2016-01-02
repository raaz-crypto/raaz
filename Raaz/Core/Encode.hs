--
module Raaz.Core.Encode
       ( -- * The encodable type
         -- $encodable$
         Encodable(..)
       -- * Encoding formats
       -- $encodingformat$
       , Format(..)
       , encode, decode, unsafeDecode
       -- ** The base 16 encoding fromat
       , Base16, fromBase16, showBase16
       ) where

import Raaz.Core.Encode.Internal
import Raaz.Core.Encode.Base16

-- $encodable$
--
-- Many types like cryptographic hashes, secret keys etc can be
-- encoded into bytes. This module gives an interface to such objects
-- using the `Encodable` type class. To ease their printing most types
-- of this class have a `Show` instances. Similarly, to make it easy
-- to defines constants of these types in source code, they often are
-- instances of `Data.String.IsString`. Typically for cryptographic
-- types like hashes, secret keys etc the `Show` and
-- `Data.String.IsString` instances correspond to the base-16 encoding
-- of these types.




-- $encodingformat$
--
-- We also give facilities to encode any instance of `Encodable` into
-- multiple formats. For type safety, encoding formats are
-- distinguished by their types. All such formats have to be members
-- of the `Format` type class and this allows encoding and decoding
-- any type that is an instance of `Encodable` into any of the desired
-- format.
--
