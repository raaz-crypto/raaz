{-|

Some utility function for byte strings.

-}

{-# LANGUAGE FlexibleContexts #-}
module Raaz.Core.Util.ByteString
       ( length, replicate
       , fromByteString, fromByteStringStorable, vectorFromByteString
       , createFrom
       , withByteString
       , unsafeCopyToCryptoPtr
       , unsafeNCopyToCryptoPtr

       ) where

import           Prelude            hiding (length, replicate)
import qualified Data.ByteString    as B
import           Data.ByteString    (ByteString)
import           Data.ByteString.Internal( toForeignPtr
                                         , create
                                         )
import           Data.Word
import qualified Data.Vector.Generic as G
import           Foreign.ForeignPtr (withForeignPtr)
import           Foreign.Ptr        (castPtr, plusPtr)
import           Foreign.Storable   (peek, Storable)

import           System.IO.Unsafe   (unsafePerformIO)

import           Raaz.Core.Classes
import           Raaz.Core.Util.Ptr

-- | A typesafe length for Bytestring
length :: ByteString -> BYTES Int
length = BYTES . B.length

-- | A type safe version of replicate
replicate :: LengthUnit l => l -> Word8 -> ByteString
replicate l = B.replicate sz
  where BYTES sz = inBytes l

-- | Copy the bytestring to the crypto buffer. This operation leads to
-- undefined behaviour if the crypto pointer points to an area smaller
-- than the size of the byte string.
unsafeCopyToCryptoPtr :: ByteString   -- ^ The source.
                      -> CryptoPtr    -- ^ The destination.
                      -> IO ()
unsafeCopyToCryptoPtr bs cptr =  withForeignPtr fptr $
           \ p -> memcpy dest (p `plusPtr` offset) (BYTES n)
    where (fptr, offset,n) = toForeignPtr bs
          dest = castPtr cptr


-- | Similar to `unsafeCopyToCryptoPtr` but takes an additional input
-- @n@ which is the number of bytes (expressed in type safe length
-- units) to transfer. This operation leads to undefined behaviour if
-- either the bytestring is shorter than @n@ or the crypto pointer
-- points to an area smaller than @n@.
unsafeNCopyToCryptoPtr :: LengthUnit n
                       => n              -- ^ length of data to be copied
                       -> ByteString     -- ^ The source byte string
                       -> CryptoPtr      -- ^ The buffer
                       -> IO ()
unsafeNCopyToCryptoPtr n bs cptr = withForeignPtr fptr $
           \ p -> memcpy dest (p `plusPtr` offset) n
    where (fptr, offset,_) = toForeignPtr bs
          dest    = castPtr cptr

-- | Works directly on the pointer associated with the
-- `ByteString`. This function should only read and not modify the
-- contents of the pointer.
withByteString :: ByteString -> (CryptoPtr -> IO a) -> IO a
withByteString bs f = withForeignPtr fptr (f . flip plusPtr off . castPtr)
  where (fptr, off, _) = toForeignPtr bs

-- | Get the value from the bytestring using `load`.
fromByteString :: EndianStore k => ByteString -> k
fromByteString src = unsafePerformIO $ withByteString src (load . castPtr)

-- | Get a vector values from a byte string. This is not very fast,
-- used mainly for defining IsString instances.
vectorFromByteString :: (EndianStore a, G.Vector v a) => ByteString -> v a
vectorFromByteString str = vec
  where vec = G.fromList $ go str
        go bs | length bs >= sz = fromByteString bs : go (B.drop (fromIntegral sz) bs)
              | otherwise       = []
        undefA :: (EndianStore a, G.Vector v a) => v a -> a
        undefA _ = undefined
        sz       = byteSize $ undefA vec

-- | Get the value from the bytestring using `peek`.
fromByteStringStorable :: Storable k => ByteString -> k
fromByteStringStorable src = unsafePerformIO $ withByteString src (peek . castPtr)

-- | The IO action @createFrom n cptr@ creates a bytestring by copying
-- @n@ bytes from the pointer @cptr@.
createFrom :: LengthUnit l => l -> CryptoPtr -> IO ByteString
createFrom l cptr = create bytes filler
  where filler dest = memcpy (castPtr dest) cptr l
        BYTES bytes = inBytes l

----------------------  Hexadecimal encoding. -----------------------------------
