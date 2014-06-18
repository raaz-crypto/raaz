-- | A basic module to parse from a pointer. This a very simple parser
-- which parses a datatype from a pointer and moves the pointer by an
-- appropriate offset. No checks are done to see if the memory access
-- is proper, it is meant to be fast and not safe. So use it with
-- care.

{-# LANGUAGE FlexibleContexts #-}

module Raaz.Core.Parse.Unsafe
       ( Parser, parse, parseStorable, parseByteString
       , runParser
       , runParser'
       ) where

import Control.Applicative         ( (<$>)          )
import Control.Monad.State.Strict
import Data.ByteString             ( ByteString     )
import Foreign.ForeignPtr.Safe     ( withForeignPtr )
import Foreign.Ptr                 ( castPtr, Ptr   )
import Foreign.Storable

import Raaz.Core.Types
import Raaz.Core.Util.Ptr
import Raaz.Core.Util.ByteString        ( createFrom )

-- | A simple parser.
type Parser = StateT CryptoPtr IO

-- | Run the parser on a buffer.
runParser :: CryptoPtr -> Parser a -> IO a
runParser cptr parser = evalStateT parser cptr

-- | Run the parser on a buffer given by a foreign pointer.
runParser' :: ForeignCryptoPtr -> Parser a -> IO a
runParser' fcptr parser = withForeignPtr fcptr $ evalStateT parser

getPtr   :: Parser (Ptr a)
getPtr   = castPtr <$> get

-- | Runs an action with the pointer pointing to the current position.
performAction :: (Ptr b -> IO a) -> Parser a
performAction action = getPtr >>= lift . action

-- | Move the current pointer forward by a given amount.
moveBy :: LengthUnit l => l -> Parser ()
moveBy = modify . flip movePtr

-- | Parses a value which is an instance of Storable. Beware that this
-- parser expects that the value is stored in machine endian. Mostly
-- it is useful in defining the `peek` function in a complicated
-- `Storable` instance.
parseStorable :: Storable a => Parser a
parseStorable = do a <- performAction peek
                   moveBy $ byteSize a
                   return a

-- | Parse a crypto value. Endian safety is take into account
-- here. This is what you would need when you parse packets from an
-- external source. You can also use this to define the `load`
-- function in a compicated `EndianStore` instance.
parse :: EndianStore a => Parser a
parse = do a <- performAction load
           moveBy $ byteSize a
           return a

-- | Parses a strict bytestring of a given length.
parseByteString :: LengthUnit l => l -> Parser ByteString
parseByteString l = do bs <- performAction getBS
                       moveBy l
                       return bs
  where getBS = createFrom l
