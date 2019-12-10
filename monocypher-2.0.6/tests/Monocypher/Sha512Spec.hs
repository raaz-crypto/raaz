{-# LANGUAGE ForeignFunctionInterface #-}

module Monocypher.Sha512Spec where


import           Data.ByteString.Internal (unsafeCreate)
import           Data.ByteString.Unsafe   (unsafeUseAsCStringLen)
import qualified Foreign.Storable as Storable
import           Foreign.Ptr
import           Foreign.C.Types
import           Foreign.C.String

import           Tests.Core
import qualified Raaz.Digest.Sha512 as Sha512

foreign import ccall unsafe
    crypto_sha512 :: Ptr Word8  -- hash
                  -> Ptr CChar  -- message
                  -> CSize
                  -> IO ()

blake2bSize :: Int
blake2bSize = Storable.sizeOf (undefined :: Sha512)

monocypher_blake2b_io :: Ptr Word8 -> CStringLen -> IO ()
monocypher_blake2b_io hshPtr (ptr, l) = crypto_sha512 hshPtr ptr (toEnum l)


monocypher_blake2b :: ByteString -> Sha512
monocypher_blake2b bs = unsafeFromByteString $ unsafeCreate blake2bSize creator
  where creator ptr = unsafeUseAsCStringLen bs (monocypher_blake2b_io ptr)

spec :: Spec
spec = prop "vs cyrpto_sha512" $
       \ x ->
         monocypher_blake2b x `shouldBe` Sha512.digest x
