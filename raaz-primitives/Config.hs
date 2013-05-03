module Config
       ( (<:>)
       ) where

(<:>)  :: String -> IO a -> IO a
infixr 0 <:>

(<:>) str action = do putStr $ "    " ++ str ++ " ..."
                      x <- action
                      putStrLn " done"
                      return x
       