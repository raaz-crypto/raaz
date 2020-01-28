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

sha512Size :: Int
sha512Size = Storable.sizeOf (undefined :: Sha512)

monocypher_sha512_io :: Ptr Word8 -> CStringLen -> IO ()
monocypher_sha512_io hshPtr (ptr, l) = crypto_sha512 hshPtr ptr (toEnum l)


monocypher_sha512 :: ByteString -> Sha512
monocypher_sha512 bs = unsafeFromByteString $ unsafeCreate sha512Size creator
  where creator ptr = unsafeUseAsCStringLen bs (monocypher_sha512_io ptr)

spec :: Spec
spec = prop "monocypher vs raaz sha512" $
       \ x ->
         monocypher_sha512 x `shouldBe` Sha512.digest x
