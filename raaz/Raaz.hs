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


         -- * Supported Cryptographic operations
         -- $operations$
         --
         module Raaz.Digest
       , module Raaz.Auth
       , module Raaz.AuthEncrypt
       , module Raaz.Random
         -- ** Textual and Binary representation
         -- $textual$
       , module Raaz.Core.Encode
         -- ** Core types and operations of raaz
       , Key, Nounce, withMemory, withSecureMemory, withRandomState
         -- * Library information.
       , version
       ) where

import qualified Paths_raaz as P
import           Data.Version  (Version)

import Raaz.Core        ( Key, Nounce, withMemory, withSecureMemory)
import Raaz.Core.Encode
import Raaz.Digest
import Raaz.Auth
import Raaz.AuthEncrypt
import Raaz.Random



-- $intro$
--
-- Raaz is a cryptographic library that provides an easy to use, type
-- safe interface for cryptographic applications. Applications can get
-- their cryptography wrong and this can have disastrous consequences.
-- This can be due to the wrong choices of the underlying
-- cryptographic primitives, or due to ignoring certain implementation
-- details (reusing the key, nounce pair). To prevent this kind of
-- issues, raaz, like other modern libraries, give a very high level
-- interface with the library taking the responsibility of selecting
-- sane primitives and their correct usages. The recommended usage
-- there is to import the top level module and get going.
--
-- > module Main where
-- >
-- > import Raaz
-- >
--
-- In addition, raaz makes use of the type system of Haskell to give
-- additional guarantees:
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


-- $operations$
--
-- The raaz library provides the following cryptographic operations.
--
-- [Message Digest:] Compute a short summary of a message that can act
-- as an integrity check for the message. A computationally bound
-- adversary cannot create two distinct messages with the same
-- digest. It /does not/ ensure authentication.
--
-- [Message Authentication:] In addition to integrity, we often want
-- to ensure that a particular message has indeed come from a know
-- peer (with whom we share a secret). Message authentication is for
-- this purpose. It however, does not ensure privacy
--
-- [Message Locking:] In addition to authentication, often we want to
-- ensure that the message is private, i.e. no one other than the
-- originator (with whom we share a secret) should be able to know the
-- contents of our communication. Message lock (via authenticated encryption)
-- is for this purpose.
--
-- [Cryptographically secure random data:] We also have an interface to
-- provide cryptographically secure bytes/data.
--
-- For detailed information on the api supported, please consult the
-- documentation of the individual modules.


-- $textual$
--
-- Many cryptographic types exposed from this library like hashes,
-- message authentication, keys and nounces can be converted from/to
-- their textual representation (via the `Show`, `IsString` instances)
-- as well as binary representation (via their `Encodable` instance).
--
-- == WARNING: textual/binary encoding are not type safe
--
-- A user of the raaz library should use the explicit data types
-- instead of their encodings. There are a few security consequences
-- of violating this principle
--
-- 1. The `IsString` instance means that we represent values as string
--    within program source (via OverloadedStrings). Do not do this unless
--    it is to write unit tests as this can result in runtime bugs.
--
-- 2. Timing safe comparison will get compromised if one compares the
--    encodings (bytestring) instead of the types themselves



-- | Raaz library version number.
version :: Version
version = P.version
