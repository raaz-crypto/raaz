This command spits out never ending stream of cryptographically secure
bytes. Apart from replacing Yo-Yo Honey Singh (`raaz rand >
/dev/audio), it is used to test the quality of the randomnes produced.


> {-# LANGUAGE CPP #-}
> module Command.Rand ( rand ) where

> import Control.Applicative
> import Control.Monad.IO.Class(liftIO)
> import Data.Monoid
> import Options.Applicative
> import Raaz
> import System.IO

So much bytes generated in one go before writing to stdout.

> bufSize :: BYTES Int
> bufSize = 32 * 1024


> opts :: Parser (IO ())
> opts =   nRandomBytes . toEnum <$> argument auto (metavar "NUMBER_OF_BYTES")
>      <|> pure infinteBytes
>   where nRandomBytes n = withBuffer $ insecurely  . genBytes n
>         infinteBytes = withBuffer $ insecurely  . genInfiniteBytes
>         withBuffer = allocaBuffer bufSize




> rand :: Parser (IO ())

#if MIN_VERSION_optparse_applicative(0,13,0)
> rand = subparser $ commandGroup "Randomness" <> randCmd <> metavar "rand"
#else
> rand = subparser $ randCmd <> metavar "rand"
#endif

>   where randCmd = command "rand" $ info (helper <*> opts) $ fullDesc
>           <> header "raaz rand - Cryptographically secure pseudo random bytes."
>           <> progDesc "Generate cryptographically secure pseudo random bytes onto the stdout."




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
