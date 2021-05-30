module Command.Info where

import           Data.Version (showVersion)
import           Options.Applicative
import           Prelude
import           Raaz
import qualified Raaz.Core.CpuSupports as CpuSupports
import qualified Raaz.Auth.Blake2b
import qualified Raaz.Auth.Blake2s
import qualified Raaz.Digest.Blake2b
import qualified Raaz.Digest.Blake2s
import qualified Raaz.Digest.Sha512
import qualified Raaz.Digest.Sha256



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
                                , algorithmInfo
                                , implementationInfo
                                , cpuCapabilities
                                ]



field   :: String -> String -> IO ()
field title v = putStrLn $ title ++ ": " ++ v
section :: String -> [String] -> IO ()
section title lns = do
  putStrLn $ title ++ ":"
  mapM_ indent lns
  where indent = putStrLn . (++) "    "

algorithmInfo :: IO ()
algorithmInfo = section "Algorithm Selection" $ map unwords
  [ [ "digest:",  digestAlgorithm]
  , [ "message authentication:", authAlgorithm]
  , [ "authenticated encryption:", authEncryptAlgorithm]
  , [ "entropy:" , entropySource]
  , [ "csprg:", csprgName]
  ]

implementationInfo :: IO ()
implementationInfo = section "Implementation Info" $ map unwords

    [ [ "auth (blake2b):", Raaz.Auth.Blake2b.name]
  , [ "auth (blake2s):", Raaz.Auth.Blake2s.name]
  , [ "blake2b:", Raaz.Digest.Blake2b.name ]
  , [ "blake2s:", Raaz.Digest.Blake2s.name ]
  , [ "sha512:", Raaz.Digest.Sha512.name ]
  , [ "sha256:", Raaz.Digest.Sha256.name ]
  ]


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
                         w     = maximum $ map (length . snd) caps
                         pad x = x ++ replicate (w - length x + 3) ' '
                         display (True, c) = unwords [pad c, "- supported"]
                         display (_,c)     = unwords [pad c, "- cannot detect"]
                       in section "CPU capabilities" $  map display caps
