This is a program that spits out never ending stream of
cryptographically secure bytes. Other than being a replacement to
Yo-Yo Honey Singh (random > /dev/audio), it is used to test the
quality of the randomnes produced.


> module Command.Rand ( rand ) where

> import Control.Monad.IO.Class(liftIO)
> import System.Exit
> import System.IO
> import Text.Read
> import Raaz

So much bytes generated in one go before writing to stdout.

> bufSize :: BYTES Int
> bufSize = 32 * 1024


The usage message for the program.

> usage :: [String] -> String
> usage errs | null errs = body
>            | otherwise = "raaz: " ++ unlines errs ++ body
>   where body = unlines $ [ "Usage: raaz random [N]"
>                          , "       raaz random [-h|--help]"
>                          , ""
>                          , "Generates never ending stream of cryptographically secure random bytes."
>                          , "With the option integral argument N, stops after generating N bytes."
>                          , "   -h\t--help\tprint this help"
>                          ]


The main stuff.

> rand :: [String] -> IO ()
> rand args = case args of
>               ["-h"]     -> printHelp
>               ["--help"] -> printHelp
>               [n]        -> maybe (badArgs n) gen $ readNBytes n
>               []         -> withBuffer $ insecurely . genInfiniteBytes
>               _          -> tooManyArgs
>   where readNBytes     :: String -> Maybe (BYTES Int)
>         readNBytes   x = (toEnum <$> readMaybe x) >>= onlyPositive
>         onlyPositive x
>           | x >= 0     = Just x
>           | otherwise  = Nothing
>         badArgs n      = errorBailout ["Bar argument " ++ n ++ " expected integer (no of bytes)"]
>         tooManyArgs    = errorBailout ["too many args"]
>         gen n          = withBuffer $ insecurely . genBytes n
>         withBuffer = allocaBuffer bufSize


> printHelp :: IO ()
> printHelp = do putStrLn $ usage []
>                exitSuccess


> genInfiniteBytes :: Pointer -> RandM ()
> genInfiniteBytes ptr = goForEver
>   where goForEver = emitRand bufSize ptr >> goForEver


Generate so many bytes.

> genBytes :: BYTES Int -> Pointer-> RandM ()
> genBytes n ptr = go n
>   where go m | m >= bufSize = do emitRand bufSize ptr; go (m - bufSize)
>              | otherwise    =    emitRand m ptr


Bail out of errors

> errorBailout errs = do hPutStrLn stderr $ usage errs
>                        exitFailure


-- Emit so may random bytes.

> emitRand :: BYTES Int -> Pointer-> RandM ()
> emitRand m ptr = do
>   fillRandomBytes m ptr
>   liftIO $ hPutBuf stdout ptr $ fromIntegral m
