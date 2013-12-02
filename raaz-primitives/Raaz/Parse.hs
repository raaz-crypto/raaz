-- | A basic module to parse from a pointer. This a very simple parser
-- which parses a datatype from a pointer and moves the pointer by an
-- appropriate offset. No checks are done to see if the memory access
-- is proper, it is meant to be fast and not safe. So use it with
-- care.
--

module Raaz.Parse
       ( Parser
       , runParser
       , runParser'
       ) where

import Control.Monad.State.Strict
import Foreign.ForeignPtr.Safe ( withForeignPtr )

import Raaz.Types

-- | A simple parser.
type Parser a = StateT CryptoPtr IO a

-- | Run the parser on a buffer.
runParser :: CryptoPtr -> Parser a -> IO a
runParser cptr parser = evalStateT parser cptr

-- | Run the parser on a buffer given by a foreign pointer.
runParser' :: ForeignCryptoPtr -> Parser a -> IO a
runParser' fcptr parser = withForeignPtr fcptr $ evalStateT parser
