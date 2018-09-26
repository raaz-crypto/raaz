-- This command spits out never ending stream of cryptographically
-- secure bytes. Apart from replacing Yo-Yo Honey Singh (`raaz rand >
-- /dev/audio), it is used to test the quality of the randomnes
-- produced.

module Command.Rand ( rand ) where


import Control.Applicative
import Control.Monad         ( void )
import Control.Monad.IO.Class(liftIO)
import Options.Applicative
import Raaz
import Raaz.Entropy
import System.IO

-- So much bytes generated in one go before writing to stdout.

bufSize :: BYTES Int
bufSize = 32 * 1024


rand :: Parser (IO ())

rand = subparser $ mconcat [ commandGroup "Randomness"
                           , metavar "RANDOMNESS"
                           , randCmd
                           , entropyCmd
                           ]



randCmd :: Mod CommandFields (IO ())
randCmd = command "rand"
          $ info (helper <*> randOpts)
          $ mconcat [ fullDesc
                     , header "raaz rand - Cryptographically secure pseudo random bytes."
                     , progDesc "output cryptographically secure pseudo random bytes."
                     ]
  where randOpts = opts insecurely emitRand

entropyCmd :: Mod CommandFields (IO ())
entropyCmd = command "entropy"
             $ info (helper <*> entropyOpts)
             $ mconcat [ fullDesc
                       , header "raaz entropy - System entropy."
                       , progDesc "emit data from the system entropy pool."
                       ]
  where entropyOpts = opts id emitEntropy

opts :: Monad m
     => (m () -> IO ())                -- ^ The runner
     -> (BYTES Int -> Pointer -> m ()) -- ^ The filler
     -> Parser (IO ())
opts runner filler = nRandomBytes . toEnum <$> argument auto (metavar "NUMBER_OF_BYTES")
                     <|> pure infinteBytes
  where nRandomBytes n = withBuffer $ runner . genBytes filler n
        infinteBytes   = withBuffer $ runner . genInfiniteBytes filler
        withBuffer     = allocaBuffer bufSize




genInfiniteBytes :: Monad m
                 => (BYTES Int -> Pointer -> m ()) -- ^ The filler function
                 -> Pointer  -- ^ the buffer to fill
                 -> m ()
genInfiniteBytes filler ptr = goForEver
  where goForEver = filler bufSize ptr >> goForEver


-- Generate so many bytes.

genBytes :: Monad m
         => (BYTES Int -> Pointer -> m ())
         -> BYTES Int
         -> Pointer
         -> m ()
genBytes filler n ptr = go n
  where go m | m >= bufSize = do filler bufSize ptr; go (m - bufSize)
             | otherwise    =    filler m ptr


-- Emit so may random bytes.

emitRand :: BYTES Int -> Pointer-> RandM ()
emitRand m ptr = do
  void   $ fillRandomBytes m ptr
  liftIO $ hPutBuf stdout ptr $ fromIntegral m

emitEntropy :: BYTES Int -> Pointer -> IO ()
emitEntropy m ptr = do
  void $ getEntropy m ptr
  hPutBuf stdout ptr $ fromIntegral m
