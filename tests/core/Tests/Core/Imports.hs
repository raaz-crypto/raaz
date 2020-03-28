-- Common imports.
module Tests.Core.Imports( module E ) where
import Data.ByteString         as E (ByteString, pack)
import Data.ByteString.Char8        () -- import IsString instance for
                                       -- byte string.
import Foreign.Storable        as E (Storable, peek, poke)
import Test.Hspec              as E
import Test.Hspec.QuickCheck   as E
import Test.QuickCheck         as E
import Test.QuickCheck.Monadic as E

import Raaz.Core               as E hiding ((===), Result, (.&.))

import Raaz.Primitive.Blake2.Internal   as E
import Raaz.Primitive.ChaCha20.Internal as E hiding ( Key )
import Raaz.Primitive.Poly1305.Internal as E hiding ( Key )
import Raaz.Primitive.Sha2.Internal     as E


-- import Raaz.Hash.Sha1          as E
