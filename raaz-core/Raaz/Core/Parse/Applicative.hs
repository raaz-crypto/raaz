-- | An applicative version of parser. This provides a restricted
-- parser which has only an applicative instance.
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Core.Parse.Applicative
       ( Parser, parseWidth
       , runParser, runParser', unsafeRunParser
       , parse, parseStorable
       , parseByteString
       ) where

import           Data.ByteString           (ByteString)
import           Data.Maybe                (fromJust)
import           Data.Monoid               (Sum(..))
import           Foreign.Ptr               (castPtr)
import           Foreign.Storable          (Storable, peek)


import           Raaz.Core.MonoidalAction
import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString (createFrom)
import           Raaz.Core.Util.Ptr        (byteSize)


type BytesMonoid = Sum (BYTES Int)

-- | An applicative parser type for reading data from a pointer.
type Parser a = TwistRM IO CryptoPtr BytesMonoid a

makeParser :: LengthUnit l => l -> (CryptoPtr -> IO a) -> Parser a
makeParser l action = TwistRA { twistFieldA       = liftToFieldM action
                              , twistDisplacement = Sum (inBytes l)
                              }

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
