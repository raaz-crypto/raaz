{-|

Some basic types and classes used in the cryptographic protocols.

-}

{-# LANGUAGE MultiParamTypeClasses #-}
module Raaz.Types
       ( Buffer
       , CryptoInput (..)
       , CryptoOutput(..)
       , CryptoCoerce(..)
       ) where

import Data.Word
import Data.ByteString (ByteString)
import qualified Data.Vector.Storable.Mutable as VSM

-- | A mutable buffer of bytes.
type Buffer = VSM.IOVector Word8

-- | A type that can be the input of any crypto algorithm.
class CryptoInput a where
  -- | Convert from a given bytestring.
  fromByteString :: ByteString -> Maybe a

  -- | Reads an element from the given buffer. This operation is
  -- unsafe because we normally avoid bound checking to improve
  -- speed. Use this only when you can prove that the index is withing
  -- the bound of the buffer.
  unsafeBufferRead :: Buffer -- ^ The buffer to read from
                   -> Int    -- ^ At what location in the buffer
                   -> IO a


-- | This is the class that captures anything that can be the output
-- of a crypto algorithm.
class CryptoOutput a where
  -- | Convert the type to Bytestring. This is always required to
  -- succeed.
  toByteString :: a -> ByteString

  -- | Writes the element to the given buffer. This operation is
  -- unsafe because we normally avoid bound checking to improve
  -- speed. Use this only when you can prove that the index is within
  -- the bound of the buffer.
  unsafeBufferWrite :: Buffer  -- ^ The buffer to write to
                    -> Int     -- ^ The index to write at
                    -> a       -- ^ The value to put in.
                    -> IO ()
-- | Often we would like to feed the input of one crypto algorithm as
-- the output of the other algorithm, for e.g RSA sign the HMAC of a
-- message.
class CryptoCoerce s t where
  cryptoCoerce :: s -> t
