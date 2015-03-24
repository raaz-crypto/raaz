-- | An applicative version of parser. This provides a restricted
-- parser which has only an applicative instance.
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Core.Parse.Applicative
       ( Parser, parseWidth, parseError
       , runParser, runParser', unsafeRunParser
       , parse, parseStorable
       , parseVector, parseStorableVector
       , unsafeParseVector, unsafeParseStorableVector
       , parseByteString
       ) where

import           Data.ByteString           (ByteString)
import           Data.Maybe                (fromJust)
import           Data.Monoid               (Sum(..))
import           Data.Vector.Generic       (Vector, generateM)
import           Foreign.Ptr               (castPtr)
import           Foreign.Storable          (Storable, peek, peekElemOff)


import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString (createFrom)
import           Raaz.Core.Util.Ptr        (byteSize, loadFromIndex)


type BytesMonoid = Sum (BYTES Int)

-- | An applicative parser type for reading data from a pointer.
type Parser a = TwistRM IO CryptoPtr BytesMonoid a

makeParser :: LengthUnit l => l -> (CryptoPtr -> IO a) -> Parser a
makeParser l action = TwistRA { twistFieldA       = liftToFieldM action
                              , twistDisplacement = Sum (inBytes l)
                              }

-- | A parser that fails with a given error message.
parseError  :: String -> Parser a
parseError msg = makeParser (0 :: BYTES Int) $ \ _ -> fail msg

-- | Return the bytes that this parser will read.
parseWidth :: Parser a -> BYTES Int
parseWidth =  getSum . twistDisplacement

-- | Run the given parser.
runParser :: Parser a -> CryptoBuffer -> IO (Maybe a)
runParser pr cbuf = withCryptoBuffer cbuf $ \ sz cptr ->
  if sz < parseWidth pr then return Nothing
  else fmap Just $ unsafeRunParser pr cptr

-- | Run the parser given the
runParser' :: Parser a -> CryptoBuffer -> IO a
runParser' pr = fmap fromJust . runParser pr

-- | Run the parser without checking the length constraints.
unsafeRunParser :: Parser a -> CryptoPtr -> IO a
unsafeRunParser = runFieldM . twistFieldA

-- | The primary purpose of this function is to satisfy type checkers.
undefParse :: Parser a -> a
undefParse _ = undefined

-- | Parses a value which is an instance of Storable. Beware that this
-- parser expects that the value is stored in machine endian. Mostly
-- it is useful in defining the `peek` function in a complicated
-- `Storable` instance.
parseStorable :: Storable a => Parser a
parseStorable = pa
  where pa = makeParser (byteSize $ undefParse pa) (peek . castPtr)

-- | Parse a crypto value. Endian safety is take into account
-- here. This is what you would need when you parse packets from an
-- external source. You can also use this to define the `load`
-- function in a complicated `EndianStore` instance.
parse :: EndianStore a => Parser a
parse = pa
  where pa = makeParser (byteSize $ undefParse pa) load

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
        width     = fromIntegral n * byteSize (undefA pvec)
        undefA    :: (Storable a, Vector v a)=> Parser (v a) -> a
        undefA _  = undefined
        getA      = peekElemOff . castPtr

-- | Similar to @parseVector@ but is expected to be slightly
-- faster. It does not check whether the length parameter is
-- non-negative and hence is unsafe. Use it only if you can prove that
-- the length parameter is non-negative.
unsafeParseVector :: (EndianStore a, Vector v a) => Int -> Parser (v a)
unsafeParseVector n = pvec
  where pvec     = makeParser  width $ \ cptr -> generateM n (loadFromIndex cptr)
        width    = fromIntegral n * byteSize (undefA pvec)
        undefA   :: (EndianStore a, Vector v a)=> Parser (v a) -> a
        undefA _ = undefined

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
              | otherwise  = unsafeParseStorableVector n
