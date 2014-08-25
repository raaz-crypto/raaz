-- | An applicative version of parser. This provides a restricted
-- parser which has only an applicative instance.

module Raaz.Core.Parse.Applicative
       ( Parser, parseWidth
       , runParser, runParser', unsafeRunParser
       , parse, parseStorable
       , parseByteString
       ) where

import           Control.Applicative
import           Data.ByteString           (ByteString)
import           Foreign.Ptr               (castPtr)
import           Foreign.Storable          (Storable, peek)

import           Raaz.Core.Types
import           Raaz.Core.Util.ByteString (createFrom)
import           Raaz.Core.Util.Ptr        (byteSize, movePtr)
-- | The parser.
data Parser a =
  Parser { parseWidth  :: !(BYTES Int) -- ^ How many characters the
                          -- parser will consume.
         , parseAction :: CryptoPtr -> IO a
                          -- ^ The IO action that needs to be run to
                          -- obtain a.
         }


-- | Runs a given parser on a cryptographic buffer. If the buffer is not
-- big enough, it will return `Nothing`.
runParser :: Parser a     -- ^ the parser to run.
          -> CryptoBuffer -- ^ the buffer on which to run the parser.
          -> IO (Maybe a)
runParser pA cbuf = withCryptoBuffer cbuf $ \ sz cptr ->
  if sz < parseWidth pA then return Nothing
  else Just <$> unsafeRunParser pA cptr

-- | Similar to `runParser` but raises an error if the buffer is not
-- big enough.
runParser' :: Parser a     -- ^ the parser to run.
           -> CryptoBuffer -- ^ the buffer on which to run the parser.
           -> IO a
runParser' pA cbuf = withCryptoBuffer cbuf $ \ sz cptr ->
  if sz < parseWidth pA then fail "parse error: buffer not big enough"
  else unsafeRunParser pA cptr

-- | Runs the applicative parser on a crypto pointer. This is highly
-- unsafe because as no checks is (can be) done on the input pointer
-- to make sure that there is enough data there. Useful in the
-- declaration of Endian store.
unsafeRunParser :: Parser a -> CryptoPtr -> IO a
unsafeRunParser = parseAction

instance Functor Parser where
  fmap f pA = Parser { parseWidth  = parseWidth pA
                     , parseAction = fmap f . parseAction pA
                     }

instance Applicative Parser where
    pure = Parser 0 . const . return

    (<*>) pF pX = Parser { parseWidth  = wF + wX
                         , parseAction = action
                         }
      where wF = parseWidth pF -- width of parsing f
            wX = parseWidth pX -- width of parsing X
            action startF =   parseAction pF startF
                          <*> parseAction pX endF
                          -- X starts from where F ends
              where endF = startF `movePtr` wF


-- | The primary purpose of this function is to satisfy type checkers.
undefParse :: Parser a -> a
undefParse _ = undefined

-- | Parses a value which is an instance of Storable. Beware that this
-- parser expects that the value is stored in machine endian. Mostly
-- it is useful in defining the `peek` function in a complicated
-- `Storable` instance.
parseStorable :: Storable a => Parser a
parseStorable = pa
  where pa = Parser { parseWidth  = byteSize $ undefParse pa
                    , parseAction = peek . castPtr
                    }

-- | Parse a crypto value. Endian safety is take into account
-- here. This is what you would need when you parse packets from an
-- external source. You can also use this to define the `load`
-- function in a complicated `EndianStore` instance.
parse :: EndianStore a => Parser a
parse = pa
  where pa = Parser { parseWidth  = byteSize $ undefParse pa
                    , parseAction = load
                    }

-- | Parses a strict bytestring of a given length.
parseByteString :: LengthUnit l => l -> Parser ByteString
parseByteString l = Parser (inBytes l) $ createFrom l
