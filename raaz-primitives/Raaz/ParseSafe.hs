-- | A module to parse from CryptoBuffer. Basic checks like correct
-- memory accesses are done to avoid buffer overflow crashes.

{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DeriveDataTypeable  #-}

module Raaz.ParseSafe
       ( Parser, parse, parseStorable, parseByteString, parseRest
       , ParseException(..)
       , runParser
       ) where

import           Control.Exception
import           Control.Monad.State.Strict
import           Data.ByteString            (ByteString)
import           Data.Typeable
import           Foreign.Storable

import           Raaz.Types

import qualified Raaz.Parse                 as P

-- | A safe parser. Also stores the message bytes required in the
-- available in the buffer.
type Parser = StateT (BYTES Int) P.Parser

data ParseException = ParseOverflow
                    deriving (Show, Typeable)

instance Exception ParseException

-- | Run the parser on a buffer.
runParser :: CryptoBuffer -> Parser a -> IO a
runParser (CryptoBuffer sz cptr) parser = evalStateT (evalStateT parser sz) cptr

-- | Checks for buffer overflow errors and safely decrease the buffer
-- size.
checkAndUpdate :: BYTES Int -> Parser ()
checkAndUpdate parsesz = do
  sz <- get
  when (sz < parsesz) $ throw ParseOverflow
  modify (flip (-) parsesz)

-- | Safe version of `P.parseStorable`. Parses a value which is an
-- instance of Storable. Beware that this parser expects that the
-- value is stored in machine endian.
parseStorable :: Storable a => Parser a
parseStorable = parseWith undefined
  where
    parseWith :: Storable a => a -> Parser a
    parseWith a = do
      checkAndUpdate $ BYTES $ sizeOf a
      lift $ P.parseStorable

-- | Safe version of `P.parse`. Parse a crypto value. Endian safety is
-- take into account here. This is what you would need when you parse
-- packets from an external source.
parse :: EndianStore a => Parser a
parse = parseWith undefined
  where
    parseWith :: EndianStore a => a -> Parser a
    parseWith a = do
      checkAndUpdate $ BYTES $ sizeOf a
      lift $ P.parse

-- | Parses a strict bytestring of a given length.
parseByteString :: CryptoCoerce l (BYTES Int) => l -> Parser ByteString
parseByteString l = do
  checkAndUpdate $ cryptoCoerce l
  lift $ P.parseByteString l

-- | Parse the rest of the buffer as strict bytestring.
parseRest :: Parser ByteString
parseRest = parseByteString =<< get
