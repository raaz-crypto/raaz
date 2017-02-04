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
newtype Foo = Foo (Tuple 42 Word32) deriving (Equality, Eq)


```

A bad example. The deriving clause makes the (==) timing dependent
even if `Foo` and `Bar` have timing safe equality.

```haskell
data BadSensitiveType = BadSensitiveType Foo Bar deriving Eq

```

## Reviewing C code.

For speed, the block primitives are written in C. Most primitives have
a default word type (64-bit unsigned int for `sha512` for
example). They also have a block that is essentially an array of such
words (for `sha512` it is 16. So it will be common to see declarations
of the following kind.

```C

typedef uint64_t   Word;  /* basic unit of sha512 hash  */
#define HASH_SIZE  8      /* Number of words in a Hash  */
#define BLOCK_SIZE 16     /* Number of words in a block */

typedef Word Hash [ HASH_SIZE  ];
typedef Word Block[ BLOCK_SIZE ];

```

In such a setting, we often have a loop that goes over all the
blocks. This would typically look like the following.

```C

void foo(Block *ptr, int nblocks, ...)
{
	/* Other stuff here */

	while(nblocks > 0) /* looping over all blocks */
	{

       doSomethingOn((*ptr)[i]); /* do something on the ith word in the current block */

       -- nblocks; ++ ptr; /* move to the next block ensure these are
                            * on the same line
	                        */

	}
}

```

We would like to follow the above convention be cause it reduces the
chance of incorrect pointer arithmetic. The bugs are concentrated on
the definition of the block and word types. So if one is reviewing
such low level code, it is better to get familiarised with this
programming pattern.


Dangerous modules
=================

We document here some of the Haskell modules that do dangerous stuff
so that they can be audited more carefully. The exact dangers are
documented in the module.


1. Raaz.Cipher.ChaCha20.Recommendation.
