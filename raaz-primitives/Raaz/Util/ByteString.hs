{-|

Some utility function for byte strings.

-}
module Raaz.Util.ByteString
       ( unsafeCopyToCryptoPtr
       , unsafeNCopyToCryptoPtr
       , fillUp
       , fillUpChunks
       ) where

import qualified Data.ByteString as B
import Data.ByteString(ByteString)
import Data.ByteString.Internal(toForeignPtr, memcpy)
import Foreign.ForeignPtr(withForeignPtr)
import Foreign.Ptr(castPtr, plusPtr)

import Raaz.Types(CryptoPtr, BYTES(..))

-- | Copy the bytestring to the crypto buffer. This operation leads to
-- undefined behaviour if the crypto pointer points to an area smaller
-- than the size of the byte string.
unsafeCopyToCryptoPtr :: ByteString   -- ^ The source.
                      -> CryptoPtr    -- ^ The destination.
                      -> IO ()
unsafeCopyToCryptoPtr bs cptr =  withForeignPtr fptr $
           \ p -> memcpy dest (p `plusPtr` offset) (fromIntegral n)
    where (fptr, offset,n) = toForeignPtr bs
          dest = castPtr cptr


-- | Similar to `unsafeCopyToCryptoPtr` but takes an additional input
-- @n@ which is the number of bytes to transfer. This operation leads
-- to undefined behaviour if either the bytestring is shorter than @n@
-- or the crypto pointer points to an area smaller than @n@.
unsafeNCopyToCryptoPtr :: BYTES Int      -- ^ number of bytes to copy
                       -> ByteString     -- ^ The source byte string
                       -> CryptoPtr      -- ^ The buffer
                       -> IO ()
unsafeNCopyToCryptoPtr n bs cptr = withForeignPtr fptr $
           \ p -> memcpy dest (p `plusPtr` offset) (fromIntegral n)
    where (fptr, offset,_) = toForeignPtr bs
          dest = castPtr cptr

-- | This function tries to fill up a crypto buffer with the data from
-- the input bytestring. It returns either the number number of bytes
-- left in the buffer if the bytestring is smaller than the remaining
-- data in the cryptobuffer, or the rest of the bytestring. This
-- function is useful for running block algorithms on lazy
-- bytestrings.
fillUp :: BYTES Int  -- ^ block size
       -> CryptoPtr  -- ^ pointer to the buffer
       -> BYTES Int  -- ^ data remaining
       -> ByteString -- ^ next chunk
       -> IO (Either (BYTES Int) ByteString)
fillUp bsz cptr r bs | l < r     = do unsafeCopyToCryptoPtr bs dest
                                      return $ Left r'
                     | otherwise = do unsafeNCopyToCryptoPtr r bs dest
                                      return $ Right rest
  where l      = BYTES $ B.length bs
        r'     = r - l
        rest   = B.drop (fromIntegral r) bs
        offset = bsz - r
        dest   = (cptr `plusPtr` fromIntegral offset)
        
-- | This combinator tries to fill up the buffer from a list of chunks
-- of bytestring. If the entire bytestring fits in the buffer then it
-- returns the space left at the buffer. Otherwise it returns the
-- remaining chunks.
fillUpChunks :: BYTES Int     -- ^ buffer size
             -> CryptoPtr     -- ^ the buffer
             -> [ByteString]  -- ^ The chunks of the byte string
             -> IO (Either (BYTES Int) [ByteString])

fillUpChunks bsz cptr chunks       = go bsz chunks
    where go r []     = return $ Left r
          go r (b:bs) = do
            fill <- fillUp bsz cptr r b
            case fill of
              Left  r1 -> go r1 bs
              Right b1 -> return $ Right $ b1:bs