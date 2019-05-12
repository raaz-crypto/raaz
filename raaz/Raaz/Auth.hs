-- | Message authentication in Raaz
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
-- Given a message @M@ and a key @K@ the message authenticator is a
-- short summary @S@ of @M@ with the additional property that it is
-- cryptographically hard to compute @S@ if the key @K@ is unknown. In
-- fact some thing stronger is true: Even when the adversary knows a
-- set of messages @M₁,...,Mₙ@ and their authenticators @S₁,...Sₙ@,
-- all of which was created using the key @K@, she cannot construct a
-- message @M@ different from @M₁,...,Mₙ@ and its authenticator @S@
-- without knowing the key @K@.
--
-- The message authentication tag provides authenticity in addition to
-- integrity in the sense that only peers that know the secret key can
-- generate the tag.

-- $specific-auth$
--
-- If you want to use specific primitives for message authentication, you can use
-- one of the following modules.
--
-- * "Raaz.Auth.Blake2b"
-- * "Raaz.Auth.Blake2s"
