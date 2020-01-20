{-# LANGUAGE ForeignFunctionInterface #-}
-- | These tests compare the implementation of chacha20 of raaz and
-- that of monocypher. The only challenge here is to adjust the nounce
-- as raaz implements the ieft variants where as monocypher implements
-- the djb variant. The tests therefore works only for nounces that
-- are 64-bit wide.
module Monocypher.ChaCha20Spec where


import qualified Data.ByteString as BS
import           Data.ByteString.Internal (unsafeCreate)
import           Data.ByteString.Unsafe   (unsafeUseAsCStringLen)
import qualified Foreign.Storable as Storable
import           Foreign.Ptr
import           Foreign.C.Types
import           Foreign.C.String
import           Foreign.Marshal.Alloc

import           Raaz.Core
import qualified Raaz.Encrypt.ChaCha20 as ChaCha20
import           Tests.Core

foreign import ccall unsafe
    chacha20  :: Ptr Word8  -- key
              -> Ptr Word8  -- nounce
              -> Ptr CChar  -- text
              -> Int        -- Size
              -> Ptr Word8  -- cipher text
              -> IO ()

-- | Generate a nounce with the top 8-bits that are zeros. This is to
-- mimic the djb variant of nounce.
nounce64 :: Gen (Nounce ChaCha20)
nounce64 = do nstr <- BS.pack <$> vector 8
              let pad = BS.replicate 4 (0 :: Word8)
              return $ unsafeFromByteString $ BS.concat [pad, nstr]

monocypher_chacha20_io :: Key ChaCha20
                       -> Nounce ChaCha20
                       -> Ptr Word8
                       -> CStringLen     -- plain text
                       -> IO ()
monocypher_chacha20_io k n cPtr (pPtr, l)
  = allocaBytes kSize
    $ \ kptr ->
        allocaBytes nSize $ \ nptr ->
                              do store (castPtr kptr) k
                                 store (castPtr nptr) n
                                 -- The 64 bit nounce is at an ofset
                                 -- of 4-bytes recall that the nounce
                                 -- has its top 4-bytes as zeros.
                                 chacha20 kptr (plusPtr nptr 4) pPtr l cPtr

  where kSize = Storable.sizeOf (undefined :: Key ChaCha20)
        nSize = Storable.sizeOf (undefined :: Nounce ChaCha20)

monocypher_chacha20_encrypt :: Key ChaCha20
                            -> Nounce ChaCha20
                            -> ByteString
                            -> ByteString
monocypher_chacha20_encrypt k n bs = unsafeFromByteString $ unsafeCreate l creator
  where l = BS.length bs
        creator = unsafeUseAsCStringLen bs . monocypher_chacha20_io k n

spec :: Spec
spec = prop "monocypher vs raaz - chacha20" $
       \ k x -> forAll nounce64
                $ \ n ->
                    monocypher_chacha20_encrypt k n x `shouldBe` ChaCha20.encrypt k n x
