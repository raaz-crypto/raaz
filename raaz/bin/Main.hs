{-# LANGUAGE RecordWildCards #-}
--
-- The main function that drives other commands.
--

import Data.Version          (showVersion)
import Options.Applicative
import Raaz                  (version)

import           Command.Checksum
import           Command.Info
import           Command.Rand


data Option = ShowVersion
             | RunCommand (IO ())

progOption  :: Parser Option
progOption = flag ShowVersion ShowVersion versionMods
             <|> RunCommand <$> rand
             <|> RunCommand <$> checksum
             <|> RunCommand <$> information

  where versionMods = mconcat [ short 'v'
                              , long "version"
                              , help "Print the version of the raaz library used"
                              ]

---------------------- The main function and stuff ------------------------------
run :: Option -> IO ()
run ShowVersion      = putStrLn $ "raaz version " ++ showVersion version
run (RunCommand cmd) = cmd


main :: IO ()
main = execParser opts >>= run
  where opts = info (helper <*> progOption)
               $ mconcat [ fullDesc
                         , header "raaz - A command line interface to the raaz cryptographic library."
                         , footer "Homepage: http://github.com/raaz-crypto"
                         ]
