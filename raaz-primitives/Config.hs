module Config
       ( (<:>), inform
       , Parameters(..), defaultParameters, toString
       , define, define'
       , protectWith
       ) where

-- | The system parameters.
data Parameters = Parameters { l1Cache   :: Int
                                 -- ^ L1 cache in bytes
                             , l2Cache   :: Int
                                 -- ^ L2 cache in bytes
                             , isGCC     :: Bool
                                 -- ^ GCC (or compatiable) C compiler.
                             }

defaultParameters :: Parameters
defaultParameters = Parameters { l1Cache = 0
                               , l2Cache = 0
                               , isGCC   = False
                               }

toString :: Parameters -> String
toString p = unlines [ define "RAAZ_L1_CACHE" $ show $ l1Cache p
                     , define "RAAZ_L2_CACHE" $ show $ l2Cache p
                     , if isGCC p then define' "RAAZ_HAVE_GCC"
                                  else define' "RAAZ_PORTABLE_C"
                     ]


-- | Define a symbol.
define :: String -> String -> String
define symbol value =  unwords ["# define", symbol, value]

-- | Empty definition.
define' :: String -> String
define' symbol = define symbol ""

-- | Protect a content with an ifndef symbol define endif construct.
protectWith :: String -> String -> String
protectWith symbol content = unlines [ "# ifndef "  ++ symbol
                                     , define' symbol
                                     , content
                                     , "# endif"
                                     ]

(<:>)  :: String -> IO a -> IO a
infixr 0 <:>

(<:>) str action = do putStr $ "    " ++ str ++ " ..."
                      x <- action
                      putStrLn " done"
                      return x
inform :: String -> IO ()
inform str = putStrLn $ "    " ++ str 