module Generic.Utils where
import Test.Hspec

with :: key -> (key -> Spec) -> Spec
with key hmsto = hmsto key



shortened :: String -> String
shortened x | l <= 11    = paddedx
            | otherwise  = prefix ++ "..." ++ suffix
  where l = length x
        prefix = take  4 x
        suffix = drop (l - 4) x
        paddedx = x ++ replicate (11 - l) ' '
