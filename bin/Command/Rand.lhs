This command that spits out never ending stream of
cryptographically secure bytes. Other than being a replacement to
Yo-Yo Honey Singh (random > /dev/audio), it is used to test the
quality of the randomnes produced.


> module Command.Rand ( rand ) where

> import Control.Applicative
> import Control.Monad.IO.Class(liftIO)
> import Data.Monoid
> import Options.Applicative
> import Raaz
> import System.IO

> import qualified Usage as U

So much bytes generated in one go before writing to stdout.

> bufSize :: BYTES Int
> bufSize = 32 * 1024


> opts :: Parser (IO ())
> opts =   nRandomBytes . fromIntegral  <$> argument auto (metavar "NUMBER_OF_BYTES")
>      <|> pure infinteBytes
>   where nRandomBytes n = withBuffer $ insecurely  . genBytes n
>         infinteBytes = withBuffer $ insecurely  . genInfiniteBytes
>         withBuffer = allocaBuffer bufSize


> rand :: ParserInfo (IO ())
> rand = info (helper <*> opts) $
>        fullDesc
>        <> header "raaz rand - Cryptographically secure pseudo random bytes."
>        <> progDesc "Generate cryptographically secure pseudo random bytes onto the stdout."



> genInfiniteBytes :: Pointer -> RandM ()
> genInfiniteBytes ptr = goForEver
>   where goForEver = emitRand bufSize ptr >> goForEver


Generate so many bytes.

> genBytes :: BYTES Int -> Pointer-> RandM ()
> genBytes n ptr = go n
>   where go m | m >= bufSize = do emitRand bufSize ptr; go (m - bufSize)
>              | otherwise    =    emitRand m ptr


-- Emit so may random bytes.

> emitRand :: BYTES Int -> Pointer-> RandM ()
> emitRand m ptr = do
>   fillRandomBytes m ptr
>   liftIO $ hPutBuf stdout ptr $ fromIntegral m
