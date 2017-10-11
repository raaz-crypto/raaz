{-# LANGUAGE CPP #-}
module Command.CpuInfo where

import Data.Monoid
import Options.Applicative

import Raaz.Core.CpuSupports as CpuSupports

display :: (Bool, String) -> String
display (True, cap) = unwords ["+", cap]
display (_,cap)     = unwords ["-", cap]

cpuInfo :: Parser (IO ())


#if MIN_VERSION_optparse_applicative(0,13,0)
cpuInfo = subparser $ commandGroup "CPU capabilities" <> cpuInfoCmd <> metavar "cpuinfo"
#else
cpuInfo = subparser $ cpuInfoCmd <> metavar "cpuinfo"
#endif
  where cpuInfoCmd = command "cpuinfo" $ info (helper <*> opts) $ fullDesc
                     <> header "raaz cpuinfo - CPU capabilities detected at runtime."
                     <> progDesc "Shows the capabilities understood/detected by raaz at runtime. Recommended implementations depend on this."

        opts = pure $ mapM_ (putStrLn . display) [ (CpuSupports.sse, "sse")
                                                 , (CpuSupports.sse2, "sse2")
                                                 , (CpuSupports.sse3, "sse3")
                                                 , (CpuSupports.sse4_1, "sse4.1")
                                                 , (CpuSupports.sse4_2, "sse4.2")
                                                 , (CpuSupports.avx,    "avx")
                                                 , (CpuSupports.avx2,   "avx2")
                                                 ]
