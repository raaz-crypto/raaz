-- | Message digest in Raaz.
module Raaz.Digest
       (
         -- ** Message digest.
         --
         -- $messagedigest$

         Digest, digest, digestFile, digestSource

         -- ** Incremental processing.
         -- $incremental$
       , DigestCxt
       , startDigest, updateDigest, finaliseDigest
         --
         -- *** Specific message digests.
         -- $specific-digest$
       ) where

import GHC.TypeLits
import Raaz.Core

import qualified Raaz.V1.Digest as Digest

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
-- Message digests __DO NOT__ provide any authentication; any one
-- could have compute the digest of a given message `m` and hence says
-- nothing about the peer from whom the digest has been received. If
-- you want some guarantee on who the digest came from consider using
-- a message authenticator (see "Raaz.Auth"). In addition if you also
-- want secrecy consider using encrypted authenticator (see
-- "Raaz.AuthEncrypt")


-- $incremental$
--
-- Message digest can also be computed incrementally using a digest
-- context captured by the `DigestCxt` data type. The three functions
-- relevant for this style of operation are `startDigest`,
-- `updateDigest`, and `finaliseDigest` which respectively prepares
-- the context for a new incremental processing, updates the context
-- with an additional chunk of data, and finalises the context to
-- recover the digest. The type `DigestCxt` is an instance of the
-- class `Memory` and hence any IO action that requires a `DigestCxt`
-- as argument can be run using `withMemory`.
--
-- If the entire input is with you either as a file or a string, the
-- `digest` and `digestFile` is a much more high level interface and
-- should be preferred.


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

type Digest = Digest.Digest

-- | The context type used for incremental processing of
-- input. Incremental processing first collects data into the context
-- and when the context buffer is full, processes it in one go using
-- the digest compression routine.  parameter @n@ measures how many
-- blocks of data can be held in the context till the compression
-- routine is invoked.
type DigestCxt n  = Digest.DigestCxt n

-- | Compute the digest of a pure byte source like `B.ByteString`.
digest :: PureByteSource src
       => src  -- ^ Message
       -> Digest
digest = Digest.digest

-- | Compute the digest of file.
digestFile :: FilePath  -- ^ File to be digested
           -> IO Digest
digestFile = Digest.digestFile


-- | Compute the digest of an arbitrary byte source.
digestSource :: ByteSource src
             => src
             -> IO Digest

digestSource = Digest.digestSource

-- | Prepare the context to (re)start a session of incremental
-- processing.
startDigest :: KnownNat n
            => DigestCxt n
            -> IO ()
startDigest = Digest.startDigest


-- | Add some more data into the context, in this case the entirety of
-- the byte source src.
updateDigest :: (KnownNat n, ByteSource src)
             => src
             -> DigestCxt n
             -> IO ()
updateDigest = Digest.updateDigest

-- | Finalise the context to get hold of the digest.
finaliseDigest :: KnownNat n
               => DigestCxt n
               -> IO Digest
finaliseDigest = Digest.finaliseDigest
