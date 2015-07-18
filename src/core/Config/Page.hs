{-|

This program finds page size of the memory.

-}

module Config.Page
       ( pageSize
       ) where
import System.Info

import           Config.Monad
import qualified Config.Page.Linux as Linux

pageSize :: ConfigM Int
pageSize | os == "linux" = Linux.getPageSize
         | otherwise     = return 4096
