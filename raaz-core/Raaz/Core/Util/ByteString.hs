{-|

Some utility function for byte strings.

-}

{-# LANGUAGE FlexibleContexts #-}
module Raaz.Core.Util.ByteString
       ( unsafeCopyToCryptoPtr
       , unsafeNCopyToCryptoPtr
       , length, replicate
       , hex, toHex
       , unsafeFromHex, fromHex
       , withByteString
       , fromByteString, fromByteStringStorable
       , createFrom
       ) where

import           Prelude            hiding (length, replicate)
import           Data.Bits
import qualified Data.ByteString    as B
import           Data.ByteString    (ByteString)
import           Data.ByteString.Internal( toForeignPtr
                                         , c2w, unsafeCreate
                                         , create
                                         )
import           Data.Word
import           Foreign.ForeignPtr (withForeignPtr)
import           Foreign.Ptr        (castPtr, plusPtr)
import           Foreign.Storable   (poke, peek, Storable)

import           System.IO.Unsafe   (unsafePerformIO)

import           Raaz.Core.Types
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

-- | Converts a crypto storable instances to its hexadecimal
-- representation.
toHex :: EndianStore a => a -> ByteString
toHex = hex . toByteString

-- | Converts bytestring to hexadecimal representation.
hex :: ByteString -> ByteString
hex bs = unsafeCreate (2 * n) filler
  where (fptr, offset, n)      = toForeignPtr bs

        filler ptr = withForeignPtr fptr $
             \ bsPtr -> putBS (bsPtr `plusPtr` offset) 0 ptr

        putBS bsPtr i ptr
              | i < n     = do x <- peek bsPtr
                               put ptr x
                               putBS bsNewPtr (i+1) ptrNew
              | otherwise = return ()
          where bsNewPtr = bsPtr `plusPtr` 1
                ptrNew   = ptr `plusPtr`   2
        hexDigit x | x < 10    = c2w '0' + x
                   | otherwise = c2w 'a' + (x - 10)

        top4 x  = x `shiftR` 4
        bot4 x  = x  .&. 0x0F

        put ptr x = do poke ptr0 $ hexDigit $ top4 x
                       poke ptr1 $ hexDigit $ bot4 x
            where ptr0 = ptr
                  ptr1 = ptr `plusPtr` 1

isDigit :: Word8 -> Bool
isDigit x = x >= c2w '0' && x <= c2w '9'
{-# INLINE isDigit #-}

isLowercaseHexChar :: Word8 -> Bool
isLowercaseHexChar x = x >= c2w 'a' && x <= c2w 'f'
{-# INLINE isLowercaseHexChar #-}

isUppercaseHexChar :: Word8 -> Bool
isUppercaseHexChar x = x >= c2w 'A' && x <= c2w 'A'
{-# INLINE isUppercaseHexChar #-}

isHexWord :: Word8 -> Bool
isHexWord x = isDigit x || isLowercaseHexChar x || isUppercaseHexChar x
{-# INLINE isHexWord #-}

fromHexWord :: Word8 -> Word8
fromHexWord x
  | isDigit x             = x - c2w '0'
  | isLowercaseHexChar x  = 10 + (x - c2w 'a')
  | isUppercaseHexChar x  = 10 + (x - c2w 'A')
  | otherwise             = -1
{-# INLINE fromHexWord #-}

-- | Converts hexadecimal bytestring to binary assuming that the input
--   bytestring is hexadecimal only.
unsafeFromHex :: ByteString -> ByteString
unsafeFromHex bs = unsafeCreate nOutput filler
  where (fptr, offset, n)      = toForeignPtr bs

        nOutput    = n `quot` 2

        filler ptr = withForeignPtr fptr $
             \ bsPtr -> putBS (bsPtr `plusPtr` offset) 0 ptr

        putBS bsPtr i ptr
              | i < nOutput = do x <- peek  bsPtr
                                 y <- peek (bsPtr `plusPtr` 1)
                                 put ptr x y
                                 putBS bsNewPtr (i+1) ptrNew
              | otherwise = return ()
          where bsNewPtr = bsPtr `plusPtr` 2
                ptrNew   = ptr   `plusPtr` 1

        put ptr x y = poke ptr binaryWord
          where binaryWord = (fromHexWord x `shiftL` 4) .|.
                             fromHexWord y

-- | Converts hexadecimal encoded bytestring to binary. If the input
-- bytestring is not hexadecimal, returns Nothing.
fromHex :: ByteString -> Maybe ByteString
fromHex bs
    | n `rem` 2 /= 0     = Nothing
    | isHexByteString bs = Just (unsafeFromHex bs)
    | otherwise          = Nothing
    where isHexByteString = B.foldr foldfn True
          foldfn w sofar  = isHexWord w && sofar

-- | Works directly on the pointer associated with the
-- `ByteString`. This function should only read and not modify the
-- contents of the pointer.
withByteString :: ByteString -> (CryptoPtr -> IO a) -> IO a
withByteString bs f = withForeignPtr fptr (f . flip plusPtr off . castPtr)
  where (fptr, off, _) = toForeignPtr bs

-- | Get the value from the bytestring using `load`.
fromByteString :: EndianStore k => ByteString -> k
fromByteString src = unsafePerformIO $ withByteString src (load . castPtr)

-- | Get the value from the bytestring using `peek`.
fromByteStringStorable :: Storable k => ByteString -> k
fromByteStringStorable src = unsafePerformIO $ withByteString src (peek . castPtr)

-- | The IO action @createFrom n cptr@ creates a bytestring by copying
-- @n@ bytes from the pointer @cptr@.
createFrom :: LengthUnit l => l -> CryptoPtr -> IO ByteString
createFrom l cptr = create bytes filler
  where filler dest = memcpy (castPtr dest) cptr l
        BYTES bytes = inBytes l
