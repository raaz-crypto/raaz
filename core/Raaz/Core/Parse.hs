-- | An applicative version of parser. This provides a restricted
-- parser which has only an applicative instance.
module Raaz.Core.Parse
       ( Parser, parseWidth, parseError, runParser
       , parse, parseStorable
       , parseVector, parseStorableVector
       , parseByteString
       , skip
       ) where

import           Data.ByteString           (ByteString)
import           Data.Vector.Generic       (Vector)
import           Foreign.Storable          (Storable, peek)
import           System.IO.Unsafe          (unsafePerformIO)

import           Raaz.Core.Parse.Unsafe
import           Raaz.Core.Prelude
import           Raaz.Core.Types.Endian
import           Raaz.Core.Types.Pointer
import           Raaz.Core.Util.ByteString (createFrom, length, withByteString)

-- | Skip over some data.
skip :: LengthUnit u => u -> Parser ()
skip = flip unsafeMakeParser doNothing
  where doNothing = const $ return ()

-- | A parser that fails with a given error message.
parseError  :: String -> Parser a
parseError msg = unsafeMakeParser (0 :: BYTES Int) $ \ _ -> fail msg

-- | Runs a parser on a byte string. It returns `Nothing` if the byte string is smaller than
-- what the parser would consume.
runParser :: Parser a -> ByteString -> Maybe a
runParser pr bs
  | length bs < parseWidth pr = Nothing
  | otherwise                 = Just $ unsafePerformIO $ withByteString bs $ unsafeRunParser pr

-- | The primary purpose of this function is to satisfy type checkers.
parserToProxy   :: Parser a -> Proxy a
parserToProxy _ = Proxy

-- | Parses a value which is an instance of Storable. Beware that this
-- parser expects that the value is stored in machine endian. Mostly
-- it is useful in defining the `peek` function in a complicated
-- `Storable` instance.
parseStorable :: Storable a => Parser a
parseStorable = pa
  where pa = unsafeMakeParser (sizeOf $ parserToProxy pa) (peek . castPointer)

-- | Parse a crypto value. Endian safety is take into account
-- here. This is what you would need when you parse packets from an
-- external source. You can also use this to define the `load`
-- function in a complicated `EndianStore` instance.
parse :: EndianStore a => Parser a
parse = pa
  where pa = unsafeMakeParser (sizeOf $ parserToProxy pa) (load . castPointer)

-- | Parses a strict bytestring of a given length.
parseByteString :: LengthUnit l => l -> Parser ByteString
parseByteString l = unsafeMakeParser l $ createFrom l

-- | Similar to `parseVector` but parses according to the host
-- endian. This function is essentially used to define storable
-- instances of complicated data. It is unlikely to be of use when
-- parsing externally serialised data as one would want to keep track
-- of the endianness of the data.
parseStorableVector :: (Storable a, Vector v a) => Int -> Parser (v a)
parseStorableVector n | n < 0      = parseError $ "parseStorableVector on " ++ show n
                      | otherwise  = unsafeParseStorableVector n

-- | Parses a vector of elements. It takes care of the correct endian
-- conversion. This is the function to use while parsing external
-- data.
parseVector :: (EndianStore a, Vector v a) => Int -> Parser (v a)
parseVector n | n < 0      = parseError $ "parseVector on " ++ show n
              | otherwise  = unsafeParseVector n
