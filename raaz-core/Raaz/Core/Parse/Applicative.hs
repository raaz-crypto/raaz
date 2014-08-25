-- | An applicative version of parser. This provides a restricted
-- parser which has only an applicative instance.

module Raaz.Core.Parse.Applicative
       ( Parser, parseWidth
       , runParser, runParser', unsafeRunParser
       ) where

import Control.Applicative

import Raaz.Core.Types
import Raaz.Core.Util.Ptr ( movePtr )
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
