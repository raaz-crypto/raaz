This is a program that spits out never ending stream of
cryptographically secure bytes. Other than being a replacement to
Yo-Yo Honey Singh (random > /dev/audio), it is used to test the
quality of the randomnes produced.


> import Control.Monad.IO.Class(liftIO)
> import System.IO
> import Raaz


> bufSize :: BYTES Int
> bufSize = 32 * 1024

> main :: IO ()
> main = allocaBuffer bufSize $ do \ ptr -> insecurely $ genBytes ptr


> genBytes :: Pointer -> RandM ()
> genBytes ptr = go
>   where go = do fillRandomBytes bufSize ptr
>                 liftIO $ hPutBuf stdout ptr (fromIntegral bufSize)
>                 go
