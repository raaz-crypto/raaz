module Command.Info where

import Data.Version (showVersion)
import Options.Applicative
import Prelude
import Raaz
import qualified Raaz.Core.CpuSupports as CpuSupports
import Raaz.Random  (csprgName)
import Raaz.Entropy (entropySource)


information :: Parser (IO ())

information = subparser $ mconcat [ commandGroup "Information"
                                  , metavar "INFORMATION"
                                  , infoCmd
                                  ]

  where infoCmd = command "info" $ info (helper <*> opts)
                  $ mconcat [ fullDesc
                            , header "raaz info - Print the library information"
                            , progDesc "prints information about raaz library."
                            ]

        opts = pure $ sequence_ [ field "Library Version" $ showVersion version
                                , field "Entropy" entropySource
                                , field "CSPRG"  csprgName
                                , cpuCapabilities

                                ]



field   :: String -> String -> IO ()
field title v = putStrLn $ title ++ ": " ++ v
section :: String -> [String] -> IO ()
section title lns = do
  putStrLn $ title ++ ":"
  mapM_ indent lns
  where indent = putStrLn . (++) "    "

cpuCapabilities :: IO ()
cpuCapabilities = do sse    <- CpuSupports.sse
                     sse2   <- CpuSupports.sse2
                     sse3   <- CpuSupports.sse3
                     sse4_1 <- CpuSupports.sse4_1
                     sse4_2 <- CpuSupports.sse4_2
                     avx    <- CpuSupports.avx
                     avx2   <- CpuSupports.avx2
                     let caps  = [ (sse, "sse")
                                 , (sse2, "sse2")
                                 , (sse3, "sse3")
                                 , (sse4_1, "sse4.1")
                                 , (sse4_2, "sse4.2")
                                 , (avx,    "avx")
                                 , (avx2,   "avx2")
                                 ]
                         w     = foldl1 max $ map (length . snd) caps
                         pad x = x ++ replicate (w - length x + 3) ' '
                         display (True, c) = unwords [pad c, "- supported"]
                         display (_,c)     = unwords [pad c, "- cannot detect"]
                       in section "CPU capabilities" $  map display caps
