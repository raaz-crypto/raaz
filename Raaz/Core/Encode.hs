-- | Encoding and decoding values to formats.
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
-- [`Format`:] The class of all types that are encoding formats to binary
--     data. They are all instances of `Show` and `Data.String.IsString` for
--     ease of printing and inclusion in source code.
--
-- [`Encodable`:] The class of all types that can be encoded /into/ binary.
--
-- The combinators `encode` and `decode` allows encoding any instance of `Encodable` to
-- any of the instances of `Format`.
--
-- == Sample code that makes use of Base16 encoding.
--
-- > theAnswer :: LE Word64
-- > theAnswer = 42
-- >
-- > main = do putStr "The answer to life, universe and everything is:"
-- >           print answserInBase16
-- >    where answerInBase16 :: Base16
-- >          answerInBase16 = encode theAnswer
-- >
-- > checkAnswer :: Base16 -> Bool
-- > checkAnswer = maybe False (==theAnswer) . decode
-- >
-- > checkAnswerBS :: ByteString -> Bool
-- > checkAnswerBS = checkAnswer . fromString
--
-- In the above example, @`LE` Word64@, which captures 64-bit unsigned
-- integers is an instance of Encode (but not Word64). The encode
-- combinator then converts in into the type Base16 that is an
-- instance of `Format`. The print then uses the `Show` instance of
-- Base16 to print it as a sequence of hexadecimal
-- characters. Similarly the decode combinator in @checkAnswer@
-- decodes a base16 before comparing with the answer.
--
-- == Liberal @IsString@ instances
--
-- Certain ascii printable formats like Base16 and Base64 have a more
-- liberal `IsString` instance: they typically allow the use of spaces
-- and newline in the input to the `fromString` function . This allows
-- a more readable representation of these types when using the
-- @OverloadedStrings@ extension. See the documentation of the
-- corresponding instance declarations to see what characters are
-- ignored. However, all `Show` instance of formats are strict in the
-- sense that they do not produce any such extraneous characters.

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
