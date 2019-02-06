-- | Raaz: High level, typesafe cryptographic library.
module Raaz
       ( -- module Raaz.Cipher
         -- * Getting started
         -- $intro$

         -- ** Message digest.
         --
         -- $messagedigest$
         Digest, digest, digestFile, digestSource
         --
         -- *** Interoperability Notes
         -- $specific-digest$

         -- ** Encryption.
   --     , module Raaz.Random
       , version
       ) where

import qualified Paths_raaz as P
import           Data.Version  (Version)

import Raaz.V1

-- $intro$
--
-- Raaz is a cryptographic library that provides an easy to use, type
-- safe interface for cryptographic applications. Experience has shown
-- that applications often get compromised because of wrong primitive
-- choice (e.g. RC4 for encryption md5 for message digest). In
-- addition, security is also compromised when tricky issues like
-- nounce reuse are not taken care of. For these reasons, modern
-- libraries tend to give abstract interfaces where the discussion is
-- centred on the underlying operations like encryption, message
-- digest etc rather than the specific primitive used for achieving
-- the goal. The interface exposed from this module is of such a high
-- level nature with the library taking the responsibility of
-- selecting the sane primitives and their correct usages for the
-- user. In addition, raaz makes use of the type system of Haskell to
-- give additional guarantees:
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
-- the high level interface. We also document how to choose specific
-- primitives when interoperability is desired.
--
-- > module Main where
-- >
-- > import Raaz
-- >


-- $messagedigest$
--
-- A message digest is a short (fixed size) summary of a long message
-- which is cryptographically secure against tampering. Use a message
-- digest if all you care about is integrity: If @d@ is the digest of
-- a message @m@, then a computationally bound adversary cannot
-- produce another message @m'@ for which the digest is also
-- @d@. Typically, cryptographic hash functions are what are used as
-- message digest.
--
-- Here is a simple application for computing and verifying the digest
-- of a file.
--
--
-- > -- Program to compute the message digest of a file
-- >
-- > import Raaz
-- > import System.Environment
-- >
-- > main = getArgs >>= digestFile . head >>= print
-- >
--
-- > -- Program to verify the integrity of a file
-- >
-- > import Raaz
-- > import System.Environment
-- >
-- > main = do [d,file] <- getArgs
-- >           dp       <- digestFile file
-- >           if fromString d == dp
-- >              then putStrLn "OK"
-- >              else putStrLn "FAILED"
-- >
--
-- There are three variants for computing the digest of a
-- message. `digest`, `digestFile` and `digestSource`.
--
-- == Warning
--
-- Message digests __DO NOT__ provide any authentication. When used to
-- check a received message @M@, using the message digest can
-- guarantee integrity only in the case when we have separately
-- confirmed the veracity of the digest in hand.

-- $specific-digest$
--
-- To inter-operate with other libraries and applications, one might
-- want to compute the digest using specific cryptographic hash. Raaz
-- supports the following:
--
-- * `Raaz.Blake2b.Blake2b`
-- * `Raaz.Blake2s.Blake2s`
-- * `Raaz.Sha512.Sha512`
-- * `Raaz.Sha256.Sha256`
--
-- Here is an example that uses sha512 to compute the digest.
--
-- > import Raaz.Sha512
-- > import System.Environment
-- >
-- > main = getArgs >>= digestFile . head >>= print
-- >

-- | Raaz library version number.
version :: Version
version = P.version
