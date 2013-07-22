{-| The configuration monad -}
module Raaz.Config.Monad
       ( ConfigM
       , doIO
       , genConfigContents, genConfigFile
       , define, define'
       , undef, hash
       , wrapHeaderFile
       , comment, newline
       , text
       ) where

import Control.Monad.Writer

-- | The configuration action.
type ConfigM a = WriterT [String] IO a

-- | Perform IO
doIO :: IO a -> ConfigM a
doIO = lift

-- | Generate the config file from the config action.
genConfigContents :: ConfigM a -> IO String
genConfigContents = fmap unlines . execWriterT

-- | Generate the config file from the config actions
genConfigFile :: FilePath -> ConfigM a -> IO ()
genConfigFile fp action = genConfigContents action >>= writeFile fp

-- | Generate a cpp line
hash :: String  -- ^ The command
     -> [String]  -- ^ the rest of the line
     -> ConfigM ()
hash command rest = tell [unwords $ ["#", command] ++ rest]

-- | Define a symbol.
define :: String -> String -> ConfigM ()
define symbol value =  hash "define" $ [symbol, value]

-- | Empty definition.
define' :: String -> ConfigM ()
define' symbol = define symbol ""

-- | Undefine a symbol
undef :: String -> ConfigM ()
undef symbol = hash "undef" [symbol]

-- | Wrap the CPP directive in a ifndef - define -endif combination.
wrapHeaderFile :: String      -- ^ Symbol to use for protection
               -> ConfigM a   -- ^ Body
               -> ConfigM ()
wrapHeaderFile symbol action = ifndef symbol $ do
  define' symbol
  newline >> action >> newline

-- | An ifndef stuff.
ifndef :: String     -- ^ symbol
       -> ConfigM a  -- ^ body
       -> ConfigM ()
ifndef symbol action = do hash "ifndef" [symbol]
                          action
                          hash "endif" ["/* " ++ symbol ++" */"]

-- | Generate actual text in the config file
text :: [String] -> ConfigM ()
text = tell

-- | Generate a comment line
comment :: String -> ConfigM ()
comment str= text ["/* " ++ str ++ " */"]

-- | Generate a new line
newline :: ConfigM ()
newline = text [""]
