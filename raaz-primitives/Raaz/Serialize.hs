{- |

Serialization from and to CryptoBuffer.

-}

{-# LANGUAGE DefaultSignatures    #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Raaz.Serialize ( CryptoSerialize(..) ) where

import Control.Applicative
import Data.Monoid

import Raaz.Parse
import Raaz.Write
import Raaz.Types

-- | Types which can be read from or written to a CryptoBuffer.
class CryptoSerialize a where
  cryptoParse :: Parser a
  cryptoWrite :: a -> Write

instance EndianStore a => CryptoSerialize a where
  cryptoParse = parse
  cryptoWrite = write

instance (CryptoSerialize a, CryptoSerialize b) => CryptoSerialize (a,b) where
  cryptoParse = (,) <$> cryptoParse <*> cryptoParse
  cryptoWrite (a,b) = cryptoWrite a <> cryptoWrite b

instance (CryptoSerialize a, CryptoSerialize b, CryptoSerialize c) => CryptoSerialize (a,b,c) where
  cryptoParse = (,,) <$> cryptoParse <*> cryptoParse <*> cryptoParse
  cryptoWrite (a,b,c) = cryptoWrite a <> cryptoWrite b <> cryptoWrite c

instance (CryptoSerialize a, CryptoSerialize b, CryptoSerialize c, CryptoSerialize d) => CryptoSerialize (a,b,c,d) where
  cryptoParse = (,,,) <$> cryptoParse <*> cryptoParse <*> cryptoParse <*> cryptoParse
  cryptoWrite (a,b,c,d) = cryptoWrite a <> cryptoWrite b <> cryptoWrite c <> cryptoWrite d
