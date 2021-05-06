-- | Message authentication in Raaz.
module Raaz.Auth
       ( -- ** Message authentication.
         --
         -- $messageauth$
         --
         Auth
       , auth
       , authFile
       , authSource

         -- ** Incremental processing.
         -- $incremental$
       , AuthCxt
       , startAuth, updateAuth, finaliseAuth

         --
         -- *** Specific message authentication algorithms
         -- $specific-auth$
         --
       ) where

import GHC.TypeLits
import Raaz.Core


import qualified Raaz.V1.Auth as Auth




-- $messageauth$
--
-- Given a message @M@ the message authenticator computed using the
-- key @K@ is a short summary @S@ of @M@ with the additional property
-- that it is cryptographically hard to compute @S@ if the key @K@ is
-- unknown. In fact some thing stronger is true: Even when the
-- adversary knows a set of messages @M₁,...,Mₙ@ and their
-- authenticators @S₁,...Sₙ@, all of which was created using the key
-- @K@, she cannot construct a message @M@ different from @M₁,...,Mₙ@
-- and its authenticator @S@ without knowing the key @K@.
--
-- In addition to proving /integrity/, the authenticator @s@ proves
-- the /authenticity/ of the message @m@ --- if one knows the secret
-- @K@, on successful verification of the authenticator, one can be
-- convinced that the message could only have originated from a peer
-- who knows @K@.
--
-- == Warning
--
-- Message authentication __does not__ provide secrecy of the message,
-- use encrypted authenticator instead "Raaz.AuthEncrypt".
--


-- | The type of authentication tag.
type Auth  = Auth.Auth

-- | Compute the authenticator of a pure byte source like,
-- `B.ByteString`.
auth :: PureByteSource src
     => Key Auth
     -> src  -- ^ Message
     -> Auth
auth = Auth.auth

-- | Compute the authenticator for a file.
authFile :: Key Auth
         -> FilePath  -- ^ File to be authed
         -> IO Auth
authFile = Auth.authFile

-- | Compute the authenticator of an arbitrary byte source.
authSource :: ByteSource src
           => Key Auth
           -> src
           -> IO Auth
authSource = Auth.authSource

-- $incremental$
--
-- Message authenticator can also be computed incrementally using a
-- authenticator context captured by the `AuthCxt` data type. The
-- three functions relevant for this style of operation are
-- `startAuth`, `updateAuth`, and `finaliseAuth` which respectively
-- prepares the context for a new incremental processing, updates the
-- context with an additional chunk of data, and finalises the context
-- to recover the digest. The type `AuthCxt` is an instance of the
-- class `Memory` and hence any IO action that requires a `AuthCxt` as
-- argument can be run using the `withMemory` combinator.
--
-- If the entire input is with you either as a file or a string, the
-- `auth` and `authFile` is a much more high level interface and
-- should be preferred.

-- | The authentication context for incremental computation of auth
-- tag.
type AuthCxt = Auth.AuthCxt

-- | Prepare the context to (re)start a session of incremental
-- processing.
startAuth :: KnownNat n
          => Key Auth   -- ^ The key to be used
          -> AuthCxt n
          -> IO ()
startAuth = Auth.startAuth

-- | Add some more data into the context, in this case the entirety of
-- the byte source src.
updateAuth :: (KnownNat n, ByteSource src)
           => src
           -> AuthCxt n
           -> IO ()
updateAuth = Auth.updateAuth

-- | Finalise the context to get hold of the digest.
finaliseAuth :: KnownNat n
             => AuthCxt n
             -> IO Auth
finaliseAuth = Auth.finaliseAuth


-- $specific-auth$
--
-- If interoperability with other applications demands the use of a
-- specific primitive for message authentication, you can use one of
-- these more specific modules.
--
-- * Raaz.Auth.Blake2b
-- * Raaz.Auth.Blake2s
