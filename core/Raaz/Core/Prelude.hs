{-# LANGUAGE CPP #-}
module Raaz.Core.Prelude ( module X
                         , module Prelude
#if !MIN_VERSION_base(4,11,0)
                         , Semigroup(..)
#endif
                         ) where

import Control.Applicative          as X
import Control.Monad                as X
import Data.Bits                    as X
import Data.ByteString.Char8           ()
import Data.ByteString.Lazy.Char8      ()
import Data.Maybe                   as X
import Data.Proxy                   as X
#if !MIN_VERSION_base(4,11,0)
import Data.Semigroup ( Semigroup(..))
#endif

import Data.String             as X
import Data.Word               as X
import Prelude hiding (length, replicate, zipWith)
import System.IO               as X
