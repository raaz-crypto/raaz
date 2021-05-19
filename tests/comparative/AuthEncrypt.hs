module AuthEncrypt (lockVsUnlock
                   , module Compare
                   ) where
import Compare

type LockFn  k n a = k -> n -> ByteString -> a
type UnlockFn k n a = k -> a -> Maybe ByteString


lockVsUnlock :: ( Show k, Show n
                , Arbitrary k, Arbitrary n
                )
             => [ (String, LockFn k n a) ]
             -> [ (String, UnlockFn k n a) ]
             -> Spec
lockVsUnlock lfs ulfs = sequence_ [ lVsUL lnf ulnf | lnf <- lfs , ulnf <- ulfs ]
  where lVsUL (ln, lf) (uln, ulf) = let
          mesg = unwords ["lock using", ln, "unlock using", uln]
          in prop mesg $ \ k n bs -> ulf k (lf k n bs) `shouldBe` Just bs
