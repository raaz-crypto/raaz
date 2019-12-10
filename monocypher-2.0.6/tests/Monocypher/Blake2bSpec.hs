{-# LANGUAGE ForeignFunctionInterface #-}

module Monocypher.Blake2bSpec where


import           Data.ByteString.Internal (unsafeCreate)
import           Data.ByteString.Unsafe   (unsafeUseAsCStringLen)
import qualified Foreign.Storable as Storable
import           Foreign.Ptr
import           Foreign.C.Types
import           Foreign.C.String

import           Tests.Core
import qualified Raaz.Digest.Blake2b as Blake2b

foreign import ccall unsafe
    crypto_blake2b :: Ptr Word8  -- hash
                   -> Ptr CChar  -- message
                   -> CSize
                   -> IO ()

blake2bSize :: Int
blake2bSize = Storable.sizeOf (undefined :: Blake2b)

monocypher_blake2b_io :: Ptr Word8 -> CStringLen -> IO ()
monocypher_blake2b_io hshPtr (ptr, l) = crypto_blake2b hshPtr ptr (toEnum l)


monocypher_blake2b :: ByteString -> Blake2b
monocypher_blake2b bs = unsafeFromByteString $ unsafeCreate blake2bSize creator
  where creator ptr = unsafeUseAsCStringLen bs (monocypher_blake2b_io ptr)

spec :: Spec
spec = prop "vs cyrpto_blake2b" $
       \ x ->
         monocypher_blake2b x `shouldBe` Blake2b.digest x
