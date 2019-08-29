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
         --
         -- *** Specific message authentication algorithms
         -- $specific-auth$
         --
       ) where
import Raaz.V1.Auth

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
-- Message authentication __does not__ provide secrecy of the message
--
-- @m@.


-- $specific-auth$
--
-- If interoperability with other applications demands the use of a
-- specific primitive for message authentication, you can use one of
-- these more specific modules.
--
-- * Raaz.Auth.Blake2b
-- * Raaz.Auth.Blake2s
