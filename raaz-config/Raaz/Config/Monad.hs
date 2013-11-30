{-|

The configuration monad.

-}
module Raaz.Config.Monad
       ( ConfigM
       , doIO
       , message, messageLn
       , genConfigContents, genConfigFile
       , define, define'
       , undef, hash
       , wrapHeaderFile
       , comment, newline
       , text
       ) where

import Control.Monad.Writer

-- | The configuration action. All the configuration actions happen in
-- this monad. The raaz packages configuration consists of some simple
-- tests that are performed on the platform followed by writing out a
-- C header file with appropriate symbols defined. Inside the
-- configuration monad you can at any time define/undefine symbols,
-- besides minimal IO actions required to carry out the tests. The
-- configuration monad keeps track of these definitions and can
-- generate a C header file in the end (either via `genConfigContents`
-- or `genConfigFile`).
type ConfigM a = WriterT [String] IO a

-- | Perform IO
doIO :: IO a -> ConfigM a
doIO = lift

-- | Print out an information message when configuring stuff.
message :: String -> ConfigM ()
message = doIO . putStr

-- | Similar to message but puts a newline as well.
messageLn :: String -> ConfigM ()
messageLn = doIO . putStrLn

-- | Generate the config file contents from the config action.
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
define symbol value =  hash "define" [symbol, value]

-- | Empty definition.
define' :: String -> ConfigM ()
define' symbol = define symbol ""

-- | Undefine a symbol
undef :: String -> ConfigM ()
undef symbol = hash "undef" [symbol]

-- | Wrap the CPP directive in a ifndef - define -endif combination.
wrapHeaderFile :: String      -- ^ Symbol to use for protection
               -> ConfigM a   -- ^ Body
               -> ConfigM a
wrapHeaderFile symbol action = ifndef symbol $ do
  define' symbol
  newline
  res <- action
  newline
  return res

-- | An ifndef stuff.
ifndef :: String     -- ^ symbol
       -> ConfigM a  -- ^ body
       -> ConfigM a
ifndef symbol action = do hash "ifndef" [symbol]
                          res <- action
                          hash "endif" ["/* " ++ symbol ++" */"]
                          return res

-- | Generate actual text in the config file
text :: [String] -> ConfigM ()
text = tell

-- | Generate a comment line
comment :: String -> ConfigM ()
comment str= text ["/* " ++ str ++ " */"]

-- | Generate a new line
newline :: ConfigM ()
newline = text [""]
