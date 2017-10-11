{-# LANGUAGE CPP #-}
module Command.Info where

import Data.Monoid
import Data.Version (showVersion)
import Options.Applicative
import Raaz
import Raaz.Core.CpuSupports as CpuSupports
import Raaz.Random.Internal


information :: Parser (IO ())

#if MIN_VERSION_optparse_applicative(0,13,0)
information = subparser $ commandGroup "Information" <> infoCmd <> metavar "info"
#else
information = subparser $ infoCmd <> metavar "info"
#endif
  where infoCmd = command "info" $ info (helper <*> opts) $ fullDesc
                     <> header "raaz info - Print the library information"
                     <> progDesc "Prints information about raaz library."

        opts = pure $ sequence_ [ field "Library Version" $ showVersion version
                                , field "Entropy" entropySource
                                , field "CSPRG"  csPRG
                                , cpuCapabilities

                                ]



field   :: String -> String -> IO ()
field title value = putStrLn $ title ++ ": " ++ value
section :: String -> [String] -> IO ()
section title lines = do
  putStrLn $ title ++ ":"
  mapM_ indent lines
  where indent = putStrLn . (++) "    "

cpuCapabilities :: IO ()
cpuCapabilities = section "CPU capabilities"
                  $ map display $ [ (CpuSupports.sse, "sse")
                                  , (CpuSupports.sse2, "sse2")
                                  , (CpuSupports.sse3, "sse3")
                                  , (CpuSupports.sse4_1, "sse4.1")
                                  , (CpuSupports.sse4_2, "sse4.2")
                                  , (CpuSupports.avx,    "avx")
                                  , (CpuSupports.avx2,   "avx2")
                                  ]
                  where display (True, cap) = unwords ["+", cap]
                        display (_,cap)     = unwords ["-", cap]
