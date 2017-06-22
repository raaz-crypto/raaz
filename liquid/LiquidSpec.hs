import Control.Monad
import Language.Haskell.Liquid.Liquid
import System.Exit
import System.Directory
import System.FilePath

-- | Liquid haskell is run on these files/directors. If the given name
-- is a directory we recurse on all .hs/.lhs files in that directory.
toCheck :: [FilePath]
toCheck = [ "Raaz/Core/Encode"
          , "Raaz/Core/Types/Tuple.hs"
          , "Raaz/Hash/Sha1"
          , "Raaz/Hash/Sha224"
          , "Raaz/Hash/Sha256"
          , "Raaz/Hash/Sha384"
          , "Raaz/Hash/Sha512"
          ]

main :: IO ()
main = do allHsFiles toCheck >>= liquid


allHsFiles :: [FilePath] -> IO [FilePath]
allHsFiles = fmap concat . mapM allHsFile

allHsFile :: FilePath -> IO [FilePath]
allHsFile fp = doesFileExist fp >>= handleFile

  where handleFile cond
           | cond && checkHs fp = return [fp]
           | cond               = return []
           | otherwise          = doesDirectoryExist fp >>= handleDir

        handleDir cond
           | cond       = recurse
           | otherwise  = return []

        recurse = listDirectory fp >>= allHsFiles . map (fp</>)

        checkHs fp = ext == ".hs" || ext == ".lhs"
          where ext = takeExtension fp
