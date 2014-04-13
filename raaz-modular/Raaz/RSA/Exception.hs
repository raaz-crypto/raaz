{- |

Exceptions which can be thrown by RSA

-}
{-# LANGUAGE DeriveDataTypeable #-}
module Raaz.RSA.Exception (RSAException(..)) where

import Data.Typeable
import Control.Exception

-- | Exceptions for RSA
data RSAException = IntegerTooLarge
                  | MessageRepresentativeOutOfRange
                  | CiphertextRepresentativeOutOfRange
                  | SignatureRepresentativeOutOfRange
                  | MessageTooLong
                  | DecryptionError
                  | EncodingError
                  | IntendedEncodedMessageLengthTooShort
                  | MaskTooLong
                  deriving (Eq,Show,Typeable)

-- | Exception instance
instance Exception RSAException
