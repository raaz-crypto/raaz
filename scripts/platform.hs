-- This script processes platform cabal file and can be used to print
-- interesting information from it. It is used to set the ghc version
-- and constraints supported by the platform.

{-# LANGUAGE OverloadedStrings #-}
import Control.Applicative
import Data.List
import Data.Maybe
import Data.Version
import Distribution.Compiler
import Distribution.Package
import Distribution.PackageDescription
import Distribution.PackageDescription.Parse
import Distribution.Text
import Distribution.Version
import Distribution.Verbosity
import System.Environment
import System.IO
import Text.PrettyPrint

---------------- Platforms and its description ------------------------

-- | A platform is given as an id together with the constraints
-- typically in a cabal file.
data Platform = Platform { platformId  :: PackageIdentifier
                         , ghcVersion  :: Version
                         , constraints :: [Dependency]
                         } deriving Show

-- | Parse a cabal file and recover its dependency.
getPlatform :: GenericPackageDescription -> Platform
getPlatform gdescr =
  Platform { platformId  = getID gdescr
           , ghcVersion  = getGHCVersion gdescr
           , constraints = getDependencies gdescr
           }
  where getID                   = package . packageDescription
        getGHCVersion           = getVersion
                                . getCompiler
                                . testedWith
                                . packageDescription
        getVersion (GHC,vRange) = fromMaybe errVersionRange
                                $ isSpecificVersion vRange
        getVersion _            = errVersionRange
        getCompiler  [] = errCompiler
        getCompiler xs  = head xs
        --
        -- Errors
        --
        errCompiler     = error "missing tested-with field"
        errVersionRange = error "tested-with: expecting exact ghc version"


-- | Get the dependencies in a particular cabal file.
getDependencies :: GenericPackageDescription -> [Dependency]
getDependencies gdescr =       exeDeps
                       `union` testDeps
                       `union` bmarkDeps
                       `union` libDeps
                       `union` libDeps
  where libDepsMaybe = condTreeToDependency <$> condLibrary gdescr
        exeDeps      = sectionDeps           $ condExecutables gdescr
        testDeps     = sectionDeps           $ condTestSuites gdescr
        bmarkDeps    = sectionDeps           $ condBenchmarks gdescr
        libDeps      =  fromMaybe [] libDepsMaybe
        --
        -- helpers
        --
        condTreeToDependency (CondNode _ deps _) = deps
        sectionDeps = foldl union [] . map  (condTreeToDependency . snd)

---------------------- Commands supported ------------------------------
allCommands :: [ (String, Platform -> Doc) ]
allCommands = [ ("make", makefile) ]

runCmd   ::  FilePath -> (Platform -> Doc) -> IO ()
runCmd fp cmd = readPackageDescription silent fp >>= process
  where process = print . cmd . getPlatform

makefile :: Platform -> Doc
makefile platform =
  vcat [ "#"
       , "# Auto generated Makefile.config for platform" <+> plat
       , "#"
       , "GHC_VERSION"         <+> "=" <+> ghcV
       , "PACKAGE_CONSTRAINTS" <+> "=" <+> cons
       ]
  where ghcV = text $ showVersion $ ghcVersion platform
        cons = vcat $ punctuate " \\" $ map depToDoc $ constraints platform

        plat = disp $ platformId platform
        -- The disp function puts an unnecessary space.
        depToDoc (Dependency pn vr) = disp pn <> disp vr

main :: IO ()
main = do args <- getArgs
          case args of
            [cmd, fp] -> dispatch cmd fp
            _         -> usage

dispatch :: String -> FilePath -> IO ()
dispatch cmd fp = maybe usage (runCmd fp) $ lookup cmd allCommands

usage :: IO ()
usage = hPutStrLn stderr
        $ unlines $ [ "platform CMD FILEPATH"
                    , "\twhere CMD is one of"
                    ]
        ++ [ "\t\t" ++ fst c | c <- allCommands]
