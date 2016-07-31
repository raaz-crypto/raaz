# Checklist for reviewing code.

## Timing safe equality.

All cryptographically sensitive data types should have timing safe
equality comparison. The class `Equality` is the timing safe
counterpart of the `Eq` class. All such sensitive types should define
the `Equality` instance first using the `eq` and the monoid instance
of the `Result` type. The `Eq` type should then be a simple use of
`(===)`.

Good example.

```haskell

data GoodSensitiveType = ...

instance Equality GoodSensitiveType where
	eq a b = ...

instance Eq GoodSensitiveType where
	(==) = (===)

```

Here are some other example of a good definition.

```haskell

-- makes use of the Equality instance for pair.
newtype AnotherGoodType = AGT (Foo,Bar) deriving Equality

instance Eq AnotherGoodType where
	(==) = (===)

-- | Makes use of the Equality and Eq instances of tuple types.
newtype Foo = Foo (Tuple n Word32) deriving (Equality, Eq)


```

A bad example. The deriving clause makes the (==) timing dependent
even if `Foo` and `Bar` have timing safe equality.

```haskell
data BadSensitiveType = BadSensitiveType Foo Bar deriving Eq

```
