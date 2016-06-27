module Raaz.Core.Encode
       ( -- * Encoding of binary data.
         -- $encodable$
         Encodable(..)
       , Format(..)
       , encode, decode, unsafeDecode
       -- ** Supported encoding formats.
       , Base16, Base64
       -- ** Helper function for base16
       , fromBase16, showBase16
       ) where

import Raaz.Core.Encode.Internal
import Raaz.Core.Encode.Base16
import Raaz.Core.Encode.Base64

-- $encodable$
--
-- Often one wants to represent cryptographic hashes, secret keys or
-- just binary data into various enocoding formats like base64,
-- hexadecimal etc. This module gives a generic interface for all such
-- operations. There are two main classes that capture the essence of
-- encoding.
--
-- [`Format`] Each encoding supported by this module is an instance of
--     this class. For printing and for easy inclusion in source code
--     appropriate instances of `Show` and `Data.String.IsString` is
--     provided for these types.
--
-- [`Encodable`] Instances of this class are those that can be encoded
--    into any of the available formats. Actual encoding and decoding
--    of elements of this class can be done by the combinators
--    `encode` and `decode`
--
-- The raaz library exposes many instances of `Format` which are all
-- some form of encoding of binary data.
--
