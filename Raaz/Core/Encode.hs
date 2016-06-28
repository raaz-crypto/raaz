module Raaz.Core.Encode
       ( -- * Encoding of binary data.
         -- $encodable$
         Encodable(..)
       , Format(..)
       , encode, decode, translate, unsafeDecode
       -- ** The base 16 encoding format
       , Base16
       , fromBase16, showBase16
       -- ** Other binary formats.
       , Base64
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

-- | Encode in a given format.
encode :: (Encodable a, Format fmt) => a -> fmt
encode = encodeByteString . toByteString

-- | Decode from a given format. It results in Nothing if there is a
-- parse error.
decode :: (Format fmt, Encodable a) => fmt -> Maybe a
decode = fromByteString . decodeFormat

-- | The unsafe version of `decode`.
unsafeDecode :: (Format fmt, Encodable a) => fmt -> a
unsafeDecode = unsafeFromByteString . decodeFormat

-- | Translate from one format to another.
translate :: (Format fmt1, Format fmt2) => fmt1 -> fmt2
translate = encodeByteString . decodeFormat
