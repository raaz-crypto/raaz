-- | An applicative version of parser. This provides a restricted
-- parser which has only an applicative instance.
module Raaz.Core.Parse.Applicative
       ( Parser, parseWidth, parseError, runParser
       , unsafeRunParser
       , parse, parseStorable
       , parseVector, parseStorableVector
       , unsafeParseVector, unsafeParseStorableVector
       , parseByteString
       , skip
       ) where

import           Data.ByteString           (ByteString)
import           Data.Vector.Generic       (Vector, generateM)
import           Foreign.Ptr               (castPtr)
import           Foreign.Storable          (Storable, peek, peekElemOff)
import           System.IO.Unsafe          (unsafePerformIO)

import           Raaz.Core.Prelude
import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types.Endian
import           Raaz.Core.Types.Pointer
import           Raaz.Core.Util.ByteString (createFrom, length, withByteString)


type BytesMonoid   = BYTES Int
type ParseAction   = FieldM IO (Ptr Word8)

-- | An applicative parser type for reading data from a pointer.
type Parser = TwistRF ParseAction BytesMonoid

makeParser :: LengthUnit l => l -> (Ptr Word8 -> IO a) -> Parser a
makeParser l action = TwistRF (liftToFieldM action) $ inBytes l

-- | Skip over some data.
skip :: LengthUnit u => u -> Parser ()
skip = flip makeParser $ const $ return ()

-- | A parser that fails with a given error message.
parseError  :: String -> Parser a
parseError msg = makeParser (0 :: BYTES Int) $ \ _ -> fail msg

-- | Return the bytes that this parser will read.
parseWidth :: Parser a -> BYTES Int
parseWidth =  twistMonoidValue


-- | Runs a parser on a byte string. It returns `Nothing` if the byte string is smaller than
-- what the parser would consume.
runParser :: Parser a -> ByteString -> Maybe a
runParser pr bs
  | length bs < parseWidth pr = Nothing
  | otherwise                 = Just $ unsafePerformIO $ withByteString bs $ unsafeRunParser pr

-- | Run the parser without checking the length constraints.
unsafeRunParser :: Parser a -> Ptr Word8 -> IO a
unsafeRunParser = runFieldM . twistFunctorValue

-- | The primary purpose of this function is to satisfy type checkers.
parserToProxy   :: Parser a -> Proxy a
parserToProxy _ = Proxy

-- | Parses a value which is an instance of Storable. Beware that this
-- parser expects that the value is stored in machine endian. Mostly
-- it is useful in defining the `peek` function in a complicated
-- `Storable` instance.
parseStorable :: Storable a => Parser a
parseStorable = pa
  where pa = makeParser (sizeOf $ parserToProxy pa) (peek . castPtr)

-- | Parse a crypto value. Endian safety is take into account
-- here. This is what you would need when you parse packets from an
-- external source. You can also use this to define the `load`
-- function in a complicated `EndianStore` instance.
parse :: EndianStore a => Parser a
parse = pa
  where pa = makeParser (sizeOf $ parserToProxy pa) (load . castPtr)

-- | Parses a strict bytestring of a given length.
parseByteString :: LengthUnit l => l -> Parser ByteString
parseByteString l = makeParser l $ createFrom l

-- | Similar to @parseStorableVector@ but is expected to be slightly
-- faster. It does not check whether the length parameter is
-- non-negative and hence is unsafe. Use it only if you can prove that
-- the length parameter is non-negative.
unsafeParseStorableVector :: (Storable a, Vector v a) => Int -> Parser (v a)
unsafeParseStorableVector n = pvec
  where pvec      = makeParser  width $ \ cptr -> generateM n (getA cptr)
        width     = fromIntegral n * sizeOf (thisProxy pvec)
        getA      = peekElemOff . castPtr
        thisProxy    :: Storable a => Parser (v a) -> Proxy a
        thisProxy _ = Proxy

-- | Similar to @parseVector@ but is expected to be slightly
-- faster. It does not check whether the length parameter is
-- non-negative and hence is unsafe. Use it only if you can prove that
-- the length parameter is non-negative.
unsafeParseVector :: (EndianStore a, Vector v a) => Int -> Parser (v a)
unsafeParseVector n = pvec
  where pvec     = makeParser  width $ \ cptr -> generateM n (loadFromIndex (castPtr cptr))
        width    = fromIntegral n * sizeOf (thisProxy pvec)
        thisProxy    :: Storable a => Parser (v a) -> Proxy a
        thisProxy _ = Proxy

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
