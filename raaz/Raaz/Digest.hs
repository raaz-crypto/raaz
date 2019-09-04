-- | Message digest in Raaz.
module Raaz.Digest
       (
         -- ** Message digest.
         --
         -- $messagedigest$

         Digest, digest, digestFile, digestSource
         --
         -- *** Specific message digests.
         -- $specific-digest$
       ) where

import Raaz.V1.Digest

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
-- Message digests __DO NOT__ provide any authentication, use the
-- message authenticator `Auth` instead.

-- $specific-digest$
--
-- To inter-operate with other libraries and applications, one might
-- want to compute the digest using specific cryptographic hash. In
-- such a situation, import one of the more specific module instead of
-- this one.
--
-- * Raaz.Digest.Blake2b
-- * Raaz.Digest.Blake2s
-- * Raaz.Digest.Sha512
-- * Raaz.Digest.Sha256
--
-- Here is an example that uses sha512 to compute the digest.
--
-- > import Raaz.Digest.Sha512
-- > import System.Environment
-- >
-- > main = getArgs >>= digestFile . head >>= print
-- >
