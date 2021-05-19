{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}

module Raaz.Digest.Blake2Spec where

import           Prelude hiding (replicate)

import           Tests.Core
import           Data.Attoparsec.ByteString.Char8 as AP
import qualified Data.ByteString                  as BS
import           Data.Char
import           Raaz.Primitive.Keyed.Internal
import           Paths_raaz

import qualified Blake2b.Digest as B2b
import qualified Blake2b.Auth   as B2bAuth
import qualified Blake2s.Digest as B2s
import qualified Blake2s.Auth   as B2sAuth

spec :: Spec
spec = do
  describe "BLAKE2b" $ do
    basicEndianSpecs (undefined :: Blake2b)
    B2b.incrementalVsFull
    B2bAuth.incrementalVsFull

  describe "BLAKE2s" $ do
    basicEndianSpecs (undefined :: Blake2s)
    B2s.incrementalVsFull
    B2sAuth.incrementalVsFull

  -- | Running the standard test cases.
  let process hand = parseWith (slurp hand) tests BS.empty
      slurp   hand = BS.hGetSome hand $ 32 * 1024
      reportFailure l str = prop l $ counterexample str False
    in do

    result <- runIO $ do
      fp    <- getDataFileName "tests/standard-test-vectors/blake2/tests.json"
      withFile fp ReadMode process

    case result of
      Done _ testCases -> mapM_ toSpec testCases
      Fail _ _ err     -> reportFailure "Parse Error" err
      _                -> reportFailure "fatal" "something terrible happened may be incomplete file"



----------------------------- Parsing functions ------------------------


data B2Test = B2b (Test Blake2b)
            | B2s (Test Blake2s)
            | Skip ByteString

data Test h = HT ByteString h
            | AT ByteString (Key (Keyed h)) (Keyed h)

toSpec :: B2Test -> Spec
toSpec tst  =
  case tst of
    B2b (HT bs h)     -> context "with blake2b" $ B2b.digestsTo bs h
    B2b (AT bs k tag) -> withKey "blake2b" k    $ bs `B2bAuth.authsTo` tag
    B2s (HT bs h)     -> context "with blake2s" $ B2s.digestsTo bs h
    B2s (AT bs k tag) -> withKey "blake2s" k    $ bs `B2sAuth.authsTo` tag
    _                 -> return ()
  where withKey hsh key = context (unwords ["with key", shortened $ show key, hsh]) . with key



hashTest :: Encodable h => Proxy h -> Parser (Test h)
hashTest _ = do  i    <- byteStringField "in" <* comma
                 kstr <- byteStringField "key" <* comma
                 if BS.null kstr then HT i <$> encodableField "out"
                   else AT i (unsafeDecode kstr) <$> encodableField "out"

b2Test :: Parser B2Test
b2Test = brace (b2bTest <|> b2sTest <|> unknown)
  where b2bTest = hashField "blake2b" >> comma >> B2b <$> hashTest (Proxy :: Proxy Blake2b)
        b2sTest = hashField "blake2s" >> comma >> B2s <$> hashTest (Proxy :: Proxy Blake2s)
        unknown = do h <- field "hash"  $ quoted $ AP.takeWhile (/= '"')
                     skipWhile (/= '}')
                     return $ Skip h



tests :: Parser [B2Test]
tests = skipSpace >> bracket (b2Test `sepBy` comma)


------------ Fields ----------------------------------
hashField :: ByteString -> Parser ByteString
hashField h = field "hash" (quoted $ string h)



byteStringField :: ByteString -> Parser ByteString
byteStringField s =  field s  (decodeFormat <$> base16)

encodableField :: Encodable a => ByteString -> Parser a
encodableField s = field s (unsafeDecode <$> base16)

base16 :: Parser Base16
base16 = hex >>= maybe (fail "bad base16 string") return
  where hex    :: Parser (Maybe Base16)
        hex    = decode <$> quoted (AP.takeWhile isHexDigit)




-- | Parse something and skip spaces.
lexeme :: Parser a -> Parser a
lexeme p = p <* skipSpace

-- A json field (key value pair).
field :: BS.ByteString -> Parser a -> Parser a
field s p = quoted (string s) >> colon >> p



-- | Some common character parsers.
lbrack      :: Parser Char
rbrack      :: Parser Char
lbrace      :: Parser Char
rbrace      :: Parser Char
colon       :: Parser Char
semiColon   :: Parser Char
quote       :: Parser Char
comma       :: Parser Char


lbrack    = lexeme $ char '['
rbrack    = lexeme $ char ']'
lbrace    = lexeme $ char '{'
rbrace    = lexeme $ char '}'
colon     = lexeme $ char ':'
semiColon = lexeme $ char ';'
comma     = lexeme $ char ','
quote     = lexeme $ char '"'

between :: Parser begin -> Parser end -> Parser a -> Parser a
between begin end p = lexeme $ do x <- begin >> p
                                  end >> return x


bracket :: Parser a -> Parser a
bracket = between lbrack rbrack

brace :: Parser a -> Parser a
brace = between lbrace rbrace

quoted :: Parser a -> Parser a
quoted = between quote quote
