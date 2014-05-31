{- |

Serialization from and to CryptoBuffer.

-}

{-# LANGUAGE DefaultSignatures    #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE UndecidableInstances #-}
module Raaz.Serialize ( CryptoSerialize(..)
                      , fromByteString
                      ) where

import Control.Applicative
import Data.Monoid
import Data.ByteString.Internal
import Foreign.ForeignPtr       (withForeignPtr)
import Foreign.Ptr              (castPtr, plusPtr)
import System.IO.Unsafe         (unsafePerformIO)

import Raaz.Core.Parse
import Raaz.Core.Write
import Raaz.Types

-- | Types which can be read from or written to a CryptoBuffer.
class CryptoSerialize a where
  cryptoParse :: Parser a
  default cryptoParse :: EndianStore a => Parser a
  cryptoParse = parse

  cryptoWrite :: a -> Write
  default cryptoWrite :: EndianStore a => a -> Write
  cryptoWrite = write

instance CryptoSerialize Word32BE
instance CryptoSerialize Word32LE
instance CryptoSerialize Word64BE
instance CryptoSerialize Word64LE

instance (CryptoSerialize a, CryptoSerialize b) => CryptoSerialize (a,b) where
  cryptoParse = (,) <$> cryptoParse
                    <*> cryptoParse
  cryptoWrite (a,b) = cryptoWrite a <> cryptoWrite b

instance ( CryptoSerialize a
         , CryptoSerialize b
         , CryptoSerialize c
         ) => CryptoSerialize (a,b,c) where
  cryptoParse = (,,) <$> cryptoParse
                     <*> cryptoParse
                     <*> cryptoParse
  cryptoWrite (a,b,c) =  cryptoWrite a
                      <> cryptoWrite b
                      <> cryptoWrite c

instance ( CryptoSerialize a
         , CryptoSerialize b
         , CryptoSerialize c
         , CryptoSerialize d
         ) => CryptoSerialize (a,b,c,d) where
  cryptoParse = (,,,) <$> cryptoParse
                      <*> cryptoParse
                      <*> cryptoParse
                      <*> cryptoParse
  cryptoWrite (a,b,c,d) =  cryptoWrite a
                        <> cryptoWrite b
                        <> cryptoWrite c
                        <> cryptoWrite d

-- | Use `CryptoSerialize` instance to parse from a ByteString.
fromByteString :: CryptoSerialize a => ByteString-> a
fromByteString src = unsafePerformIO $ withForeignPtr fptr go
  where
    (fptr, offset, len) = toForeignPtr src
    go cptr = runParser buffer cryptoParse
      where buffer = CryptoBuffer (BYTES len) (castPtr $ cptr `plusPtr` offset)
{-# NOINLINE fromByteString #-}
