module Config
       ( (<:>)
       , define, define'
       , protectWith
       ) where

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
       