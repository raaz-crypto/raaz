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
-- Given a message @M@ and a key @K@ the message authenticator is a
-- short summary @S@ of @M@ with the additional property that it is
-- cryptographically hard to compute @S@ if the key @K@ is unknown. In
-- fact some thing stronger is true: Even when the adversary knows a
-- set of messages @M₁,...,Mₙ@ and their authenticators @S₁,...Sₙ@,
-- all of which was created using the key @K@, she cannot construct a
-- message @M@ different from @M₁,...,Mₙ@ and its authenticator @S@
-- without knowing the key @K@.
--
-- The message authentication @s::`Auth`@ of a message @m@ computed
-- using a key @k :: Key Auth@, can be seen as a message digest that
-- can only be computed/verified by someone who has the knowledge of
-- the key @k@. Thus a message @m@ together with its valid
-- authentication @s@ proves authenticity (to someone who already know
-- @k@) in addition to integrity as only a peers that know the secret
-- key @k@ could have generated @s@.
--
-- == Warning
--
-- Message authentication __does not__ provide secrecy of the message
-- @m@.


-- $specific-auth$
--
-- If you want to use specific primitives for message authentication,
-- you can use one of the following modules.
--
-- * "Raaz.Auth.Blake2b"
-- * "Raaz.Auth.Blake2s"
