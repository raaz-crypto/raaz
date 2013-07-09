{-|

This module exposes the `SHA384` hash constructor. You would hardly
need to import the module directly as you would want to treat the
`SHA384` type as an opaque type for type safety. This module is
exported only for special uses like writing a test case or defining a
binary instance etc.

-}

module Raaz.Hash.Sha384.Type( SHA384(..) )where

import Raaz.Hash.Sha512.Type(SHA384(..))