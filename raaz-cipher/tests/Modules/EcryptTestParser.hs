{-# LANGUAGE OverloadedStrings #-}
module Modules.EcryptTestParser
       ( EcryptTest(..)
       , PartialStream(..)
       , parseTestVector
       )where


import           Control.Applicative
import           Data.Bits
import           Data.ByteString        (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Char8  as B8
import           Data.Char
import           Text.Parsec
import           Text.Parsec.ByteString (parseFromFile)
import           System.IO

-- | Format of Ecrypt test cases
data EcryptTest = EcryptTest String           -- ^ Name
                             ByteString       -- ^ Key
                             ByteString       -- ^ IV
                             [PartialStream]  -- ^ Stream
                             ByteString       -- ^ Xor digest
                deriving Show


data PartialStream = PartialStream { from :: Int
                                   , to   :: Int
                                   , value :: ByteString
                                   } deriving Show

fromHex :: ByteString -> ByteString
fromHex bs = B8.unfoldr with bs
  where
    with ""  = Nothing
    with acc = Just (w,rest)
      where (f,rest) = B8.splitAt 2 acc
            [a,b] = B8.unpack f
            w = chr $ (digitToInt a * 16) + digitToInt b

parseTestVector :: FilePath -> IO [EcryptTest]
parseTestVector fp = do
  eitherET <- parseFromFile parseAll fp
  case eitherET of
    Left err -> error $ show err
    Right out -> return out

parseName = do
  spaces
  s <- string "Set"
  rest <- manyTill anyChar (try newline)
  return (s ++ rest)


hexline = do
  spaces
  B8.pack <$> manyTill hexDigit (try newline)

parseKey = do
  spaces
  string "key"
  spaces
  char '='
  fromHex <$> BS.concat <$> many1 (try hexline)

parseIV = do
  spaces
  string "IV"
  spaces
  char '='
  fromHex <$> BS.concat <$> many1 (try hexline)

parseXor = do
  spaces
  string "xor-digest"
  spaces
  char '='
  fromHex <$> BS.concat <$> many1 (try hexline)

parseStream = do
  spaces
  string "stream"
  spaces
  char '['
  beg <- read <$> many1 digit
  string ".."
  end <- read <$> many1 digit
  char ']'
  spaces
  char '='
  val <- fromHex <$> BS.concat <$> many1 (try hexline)
  return $ PartialStream beg end val

parseEncryptTest = EcryptTest <$> parseName
                              <*> parseKey
                              <*> parseIV
                              <*> many1 (try parseStream)
                              <*> parseXor

parseAndSkip = do
  manyTill anyChar (try $ lookAhead $ string "Set")
  parseEncryptTest

parseAll = many1 (try parseAndSkip)
