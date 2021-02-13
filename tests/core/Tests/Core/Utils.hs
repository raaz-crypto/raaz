module Tests.Core.Utils where

import Raaz.Core.Types.Internal ( BYTES(..) )

import Tests.Core.Imports hiding (length, replicate)
import Prelude                   (length, replicate)

import Foreign.Ptr           ( castPtr )
import Data.ByteString as B  (concat)

-- | Run a spec with a give key.
with :: key -> (key -> Spec) -> Spec
with key hmsto = hmsto key


-- | Store and the load the given value.
storeAndThenLoad :: EndianStore a
                 => a -> IO a
storeAndThenLoad a = allocaBuffer (sizeOf $ pure a) (runStoreLoad . castPtr)
  where runStoreLoad ptr = store ptr a >> load ptr


allocCast      :: BYTES Int -> (Ptr a -> IO c) -> IO c
allocCast sz f = allocaBuffer sz $ f . castPtr

storeAdjustAndPeek :: EndianStore a
                   => a
                   -> IO a
storeAdjustAndPeek a
  = allocCast sz $ \ ptr -> do store ptr a
                               adjustEndian ptr 1
                               peek ptr
  where sz = sizeOf $ pure a

pokeAdjustAndLoad :: EndianStore a
                   => a
                   -> IO a
pokeAdjustAndLoad a
  = allocCast sz $ \ ptr -> do poke ptr a
                               adjustEndian ptr 1
                               load ptr
  where sz = sizeOf $ pure a



basicEndianSpecs :: ( EndianStore a, Show a, Eq a, Arbitrary a)
                  => a -> Spec
basicEndianSpecs a = describe "Endian Checks" $ do
  prop "store followed by load returns original value" $ \ x ->
    storeAndThenLoad (x `asTypeOf` a) `shouldReturn` x

  prop "store, adjust followed by peek should return the original value" $ \ x ->
    storeAdjustAndPeek (x `asTypeOf` a) `shouldReturn` x

  prop "poke, adjust followed by load should return the original value" $ \ x ->
    pokeAdjustAndLoad (x `asTypeOf` a) `shouldReturn` x



-- | Shorten a string to make it readable in tests.
shortened :: String -> String
shortened x | l <= 11    = paddedx
            | otherwise  = prefix ++ "..." ++ suffix
  where l = length x
        prefix = take  4 x
        suffix = drop (l - 4) x
        paddedx = x ++ replicate (11 - l) ' '

genEncodable :: (Encodable a, Storable a) => Gen a
genEncodable = go undefined
  where go :: (Encodable a, Storable a) => a -> Gen a
        go x = unsafeFromByteString . pack <$> vector (fromEnum $ sizeOf $ pure x)

-- | Generate bytestrings that are multiples of block size of a
-- primitive.
blocks :: Primitive prim => Proxy prim -> Gen ByteString
blocks primProxy = B.concat <$> listOf singleBlock
  where singleBlock = pack <$> vector sz
        BYTES sz    = inBytes $ blocksOf 1 primProxy


-- | Run a property with a given generator.
feed :: (Testable pr, Show a) => Gen a -> (a -> IO pr) -> Property
feed gen pr = monadicIO $ pick gen >>= (run . pr)

repeated :: Monoid m => m -> Int -> m
repeated m n = mconcat $ replicate n m
