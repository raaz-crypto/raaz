{-|

This module exposes the `SHA224` hash constructor. You would hardly
need to import the module directly as you would want to treat the
`SHA224` type as an opaque type for type safety. This module is
exported only for special uses like writing a test case or defining a
binary instance etc.

-}

module Raaz.Hash.Sha224.Type( SHA224(..) )where

import Raaz.Hash.Sha256.Type(SHA224(..))