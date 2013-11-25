{-|

This module exposes all the hash functions provided by the raaz
library. This is the interface that you would normally want to
use. You can also import the module for the individual hash function.

Hashing is provided by the generic functions `sourceHash`, `hash`, and
`hashFile`. The function `sourceHash` can be used with any instance of
`ByteSource` and it returns the hash wrapped in the IO monad. For
instances of `PureByteSource`, which include strict and lazy
`ByteString`, you can use the `hash` function. The `hashFile` hashes a
given file.  This module also export the specialised variants for
`sourceHash`, `hash` and `hashFile` for specific hashes. For example,
in the case of `SHA1` these functions are called `sourceSha1`, `sha1`
and `sha1File` respectively.

The constructors of the hash types are not exposed here; we expect the
user to use these types as an opaque type so as to get the benefits of
type checking. However, if you want to get the constructor for any of
the hash Foo you could import the module Raaz.Hash.Foo.Type.

-}


module Raaz.Hash
       ( module Raaz.Hash.Sha1
       , module Raaz.Hash.Sha224
       , module Raaz.Hash.Sha256
       , module Raaz.Hash.Sha384
       , module Raaz.Hash.Sha512
       ) where

import Raaz.Hash.Sha1
import Raaz.Hash.Sha224
import Raaz.Hash.Sha256
import Raaz.Hash.Sha384
import Raaz.Hash.Sha512
