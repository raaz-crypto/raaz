module Compare ( checkSame, message
               , module Tests.Core
               ) where
import Tests.Core
same :: Eq a => [a] -> Bool
same []     = True
same (x:xs) = all (==x) xs


checkSame :: Eq a => [(b,a)] -> Bool
checkSame = same . map snd

message :: [String] -> String
message xs = unwords $ oxfordComma $ "comparing" : xs
  where oxfordComma [x,y] = [x ++ ", and", y]
        oxfordComma ys    = ys
