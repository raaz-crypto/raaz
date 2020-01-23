-- | Raaz: High level, typesafe cryptographic library.
module Raaz
       (
         -- * Getting started
         -- $intro$
         module Raaz.Digest
       , module Raaz.Auth
       , module Raaz.Encrypt
       , module Raaz.Random
         -- * Library information.
       , version
       ) where

import qualified Paths_raaz as P
import           Data.Version  (Version)
import Raaz.Digest
import Raaz.Auth
import Raaz.Encrypt
import Raaz.Random

-- $intro$
--
-- Raaz is a cryptographic library that provides an easy to use, type
-- safe interface for cryptographic applications. It is very easy for
-- applications to get its cryptography wrong and experience has shown
-- that this is often due to the trick choices that needs to be made
-- for the cryptographic primitives (e.g. RC4 for encryption md5 for
-- message digest). This is also compounded by the fact that often
-- sound choices of the primitives can be compromised due to ignoring
-- certain implementation issues like nounce reuse.  For these
-- reasons, modern libraries tend to give abstract interfaces where
-- the discussion is centred on the underlying operations like
-- encryption, message digest etc rather than the specific primitive
-- used for achieving the goal. The interface exposed from this module
-- is of such a high level nature with the library taking the
-- responsibility of selecting the sane primitives and their correct
-- usages for the user. In addition, raaz makes use of the type system
-- of Haskell to give additional guarantees:
--
-- [Type safety:] Instead of representing cryptographic data as plain
-- strings, raaz uses distinct types for semantically distinct
-- cryptographic data. If the user inadvertently compares a
-- 'Raaz.Sha512.Sha512' digest with a `Raaz.Blake2b.Blake2b` digest,
-- the compiler will flag this as an error.
--
-- [Timing safe equality:] All cryptographically sensitive data have
-- timing safe equality operation `==`. The default comparison is
-- therefore safe. In other libraries one often have to use specific
-- functions to make timing safe comparisons which novice users tend
-- to overlook.
--
-- [Convenient Encoding:] The Show instance of most types give a
-- base16 encoding which is the convention in most cryptographic
-- literature.  More generally these types are instances of the
-- `Raaz.Core.Encode.Encodable` class and hence can be encoded to any
-- encoding `Raaz.Core.Encode.Format` supported by Raaz.
--
-- [`IsString` instances:] Although /not recommended/ due to errors
-- being thrown at runtime, there are often instances where one would
-- like to represent cryptographic values in program source
-- code. Typical examples are unit tests involving exact value of the
-- primitives. Most primitives have an `Data.String.IsString` instance
-- which accepts the base16 encoding of the value. While `show`
-- function only generate characters [0-9a-f], the
-- `Data.String.IsString` instances are liberal. Users can use
-- arbitrary combination of lower and upper case hex digest and can
-- also use the spaces and ':' (the colon character) as separators
-- (which are ignored).
--
-- Therefore, unless there is specific interoperability requirements,
-- we encourage the user to just import this top level module and use
-- the high level interface.
--
-- > module Main where
-- >
-- > import Raaz
-- >
--
-- The top level module "Raaz" exposes all the cryptographic
-- operations supported by this library.  Applications that only need
-- specific cryptographic operations can selectively import the
-- appropriate modules given below (see the module specific
-- documentation for the detailed interface for each operation).


-- | Raaz library version number.
version :: Version
version = P.version
