-- |
--
-- Module      : Raaz
-- Description : High level, type safe, cryptographic library
-- Copyright   : (c) Piyush P Kurur, 2016
-- License     : Apache-2.0 OR BSD-3-Clause
-- Maintainer  : Piyush P Kurur <ppk@iitpkd.ac.in>
-- Stability   : experimental
--
module Raaz
       (
         -- * Getting started
         -- $intro$
         module Raaz.Digest
       , module Raaz.Auth
       , module Raaz.AuthEncrypt
       , module Raaz.Random
         -- ** Running memory action.
         -- $memory$
       , module Raaz.Core
         -- * Library information.
       , version
       ) where

import qualified Paths_raaz as P
import           Data.Version  (Version)

import Raaz.Core ( withMemory, withSecureMemory)
import Raaz.Digest
import Raaz.Auth
import Raaz.AuthEncrypt
import Raaz.Random



-- $intro$
--
-- Raaz is a cryptographic library that provides an easy to use, type
-- safe interface for cryptographic applications. It is very easy for
-- applications to get its cryptography wrong and experience has shown
-- that this is often due to the choices of cryptographic primitives
-- that is to be made by the (often non-expert) user. Even correct
-- choices of the primitives can leave the user vulnerable if certain
-- implementation issues like nounce reuse has not been taken care of.
-- For these reasons, modern libraries tend to give abstract
-- interfaces where the discussion is centred on the desired
-- cryptographic operations like encryption, message digest etc rather
-- than the specific primitive used for achieving the goal. The
-- interface exposed from this module is of such a high level nature
-- with the library taking the responsibility of selecting the sane
-- primitives and their correct usages for the user. In addition, raaz
-- makes use of the type system of Haskell to give additional
-- guarantees:
--
-- [Type safety:] Instead of representing cryptographic data as plain
-- strings, raaz uses distinct types for semantically distinct
-- cryptographic data. If the user inadvertently compares a
-- 'Raaz.Sha512.Sha512' digest with a `Raaz.Blake2b.Blake2b` digest,
-- the compiler will flag this as an error. Compare this with the
-- situation in many libraries where both these are just 512-bit
-- quantities.
--
-- [Timing safe equality:] All cryptographically sensitive data have
-- timing safe equality operation `==`. The default comparison is
-- therefore safe and we encourage its use. Compare this with many
-- other libraries where one has to remember to use specific functions
-- sanitised timing safe comparisons.
--
-- [Locked memory:] The interface to locked memory is provided through
-- the combinators `withMemory` and `withSecureMemory`. These
-- combinators take any IO action that expects a memory element
-- (captured by the class `Memory`) and runs it by providing such an
-- element. The underlying memory buffer is zeroed at the end of the
-- action. In addition, `withSecureMeory` ensures that the memory
-- allocated for the memory element is locked (and hence not swapped
-- out). This gives a relatively higher level interface for locked
-- memory. A word of caution though. Interfaces that directly deal
-- with memory elements should be considered low-level code and should
-- better be left to advanced users. Furthermore certain usages,
-- particularly those that involve reading pure values out of the
-- memory element, are problematic and a lot of caution needs to be
-- employed when using this interface.
--
-- [Convenient Encoding:] The `Show` instance of most types like
-- message digest or the authenticator tag give a base16 encoding
-- which is the convention in most cryptographic literature.  More
-- generally these types are instances of the
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
-- arbitrary combination of lower or upper case hex digit. For
-- readability in source code, long hex strings can be interspersed
-- with the ' ' (space) and ':' (colon) which the `IsString` instance
-- ignores. For example, the strings "abc:def" and "Abc dE:f" all give
-- the same result as string "abcdef".
--
-- With the above points in mind, the recommended approach to use
-- raaz is by import this top level module.
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

-- $memory$
--
-- Actions that require a memory element can be executed using the two
-- combinators `withMemory` and `withSecureMemory`. Examples include
-- memory elements for incremental processing like `DigestCxt`,
-- `AuthCxt` etc.

-- | Raaz library version number.
version :: Version
version = P.version
