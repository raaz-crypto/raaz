-- This command spits out never ending stream of cryptographically
-- secure bytes. Apart from replacing Yo-Yo Honey Singh (`raaz rand >
-- /dev/audio), it is used to test the quality of the randomnes
-- produced.

module Command.Rand ( rand ) where


import Options.Applicative
import Raaz.Core
import Raaz.Random
import Raaz.Random.Internal


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
  where randOpts = opts infiniteRand finiteRand

entropyCmd :: Mod CommandFields (IO ())
entropyCmd = command "entropy"
             $ info (helper <*> entropyOpts)
             $ mconcat [ fullDesc
                       , header "raaz entropy - System entropy."
                       , progDesc "emit data from the system entropy pool."
                       ]
  where entropyOpts = opts infiniteEntropy finiteEntropy

opts :: (Ptr Word8 -> IO ())
     -> (BYTES Int -> Ptr Word8 -> IO ())
     -> Parser (IO ())
opts inf fin  = nRandomBytes . toEnum <$> argument auto (metavar "NUMBER_OF_BYTES")
                <|> pure infinteBytes
  where nRandomBytes n = withBuffer (fin n)
        infinteBytes   = withBuffer inf
        withBuffer     = allocaBuffer bufSize



------------- Rand functions ----------------------------------------------

emitRand :: BYTES Int
         -> Ptr Word8
         -> RandomState
         -> IO ()
emitRand m ptr rstate = do
  fillRandomBytes m (destination ptr) rstate
  hPutBuf stdout ptr $ fromIntegral m

infiniteRand :: Ptr Word8
             -> IO ()
infiniteRand buf = withRandomState goForEver
  where goForEver rstate = go
          where go = emitRand bufSize buf rstate >> go

finiteRand :: BYTES Int
           -> Ptr Word8
           -> IO ()
finiteRand n buf = withRandomState goFinite
  where goFinite rstate = go n
          where go m | m >= bufSize = do emitRand bufSize buf rstate ; go (m - bufSize)
                     | otherwise    =    emitRand m buf rstate



-----------------  Entropy functions ------------------------------------------

emitEntropy :: BYTES Int
            -> Ptr Word8
            -> IO ()
emitEntropy m ptr = do
  void $ fillSystemEntropy m ptr
  hPutBuf stdout ptr $ fromIntegral m


infiniteEntropy ::  Ptr Word8
                -> IO ()
infiniteEntropy buf = go
  where go = emitEntropy bufSize buf >> go

finiteEntropy:: BYTES Int
             -> Ptr Word8
             -> IO ()
finiteEntropy n buf = go n
  where go m | m >= bufSize = do emitEntropy bufSize buf ; go (m - bufSize)
             | otherwise    =    emitEntropy m buf
