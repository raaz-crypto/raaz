{-|

Some utility function for byte strings.

-}

{-# LANGUAGE FlexibleContexts #-}
module Raaz.Core.Util.ByteString
       ( length, replicate
       , create, createFrom
       , withByteString
       , unsafeCopyToPointer
       , unsafeNCopyToPointer
       ) where

import           Prelude            hiding (length, replicate)
import qualified Data.ByteString    as B
import           Data.ByteString    (ByteString)
import qualified Data.ByteString.Internal as BI
import           Data.Word
import           Foreign.ForeignPtr (withForeignPtr)
import           Foreign.Ptr        (castPtr, plusPtr)
import           Foreign.Storable   (peek, Storable)

import           System.IO.Unsafe   (unsafePerformIO)

import           Raaz.Core.Types.Pointer
import           Raaz.Core.Types.Copying

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
unsafeCopyToPointer :: ByteString   -- ^ The source.
                    -> Ptr a        -- ^ The destination.
                    -> IO ()
unsafeCopyToPointer bs cptr =  withForeignPtr fptr $
           \ p -> memcpy (destination cptr) (source $ p `plusPtr` offset) (BYTES n)
    where (fptr, offset,n) = BI.toForeignPtr bs


-- | Similar to `unsafeCopyToPointer` but takes an additional input
-- @n@ which is the number of bytes (expressed in type safe length
-- units) to transfer. This operation leads to undefined behaviour if
-- either the bytestring is shorter than @n@ or the crypto pointer
-- points to an area smaller than @n@.
unsafeNCopyToPointer :: LengthUnit n
                     => n              -- ^ length of data to be copied
                     -> ByteString     -- ^ The source byte string
                     -> Ptr a         -- ^ The buffer
                     -> IO ()
unsafeNCopyToPointer n bs cptr = withForeignPtr fptr $
           \ p -> memcpy (destination cptr) (source $ p `plusPtr` offset) n
    where (fptr, offset,_) = BI.toForeignPtr bs

-- | Works directly on the pointer associated with the
-- `ByteString`. This function should only read and not modify the
-- contents of the pointer.
withByteString :: ByteString -> (Ptr something -> IO a) -> IO a
withByteString bs f = withForeignPtr fptr (f . flip plusPtr off)
  where (fptr, off, _) = BI.toForeignPtr bs

-- | The action @create l act@ creates a length @l@ bytestring where
-- the contents are filled using the the @act@ to fill the buffer.
create :: LengthUnit l => l -> (Ptr a -> IO ()) -> IO ByteString
create l act = myCreate (act . castPtr)
  where myCreate =  BI.create $ fromIntegral $ inBytes l

-- | The IO action @createFrom n cptr@ creates a bytestring by copying
-- @n@ bytes from the pointer @cptr@.
createFrom :: LengthUnit l => l -> Ptr a -> IO ByteString
createFrom l cptr = create l filler
  where filler dptr = memcpy (destination dptr) (source cptr) l

----------------------  Hexadecimal encoding. -----------------------------------
