---
title: RAAZ(1) The Raaz Cryptographic Library | Version 0.4
author: Piyush P Kurur
date: 30 May, 2021
---

# NAME

raaz - Command line application program for the Raaz cryptographic
	   library.

# SYNOPSIS

**raaz** **[-h |\--help]** **[-v|\--version]**

**raaz** **[SUB-COMMAND]**  **[-h | \--help]**

**raaz** **[SUB-COMMAND]** **[SUB-COMMAND-OPTIONS]** **[SUB-COMMAND-ARGUMENTS]**


# DESCRIPTION

Raaz is a cryptographic library for the Haskell programming
language. One of the important design goal is to use the type system
of Haskell to catch various bugs like buffer overflows and timing
attacks at compile time. Therefore, raaz is meant to be used as
cryptographic library for applications written in Haskell.

As part of the library, we expose an *application program* (also
called **raaz**) which expose some of the implemented primitives in
the library. This man page is about the program **raaz**.

# OPTIONS

**-h**, **\--help**
:    Display help message. This option is supported by sub-commands as well
     in which case it displays the brief help of that sub-command.

**-v**, **\--version**
:    Display the version of the underlying raaz library


# SUB-COMMANDS

The program **raaz** exposes the cryptographic primitives as
sub-commands which fall into the following categories.

## Randomness

**raaz** **rand**    [BYTES_TO_GENERATE]

**raaz** **entropy** [BYTES_TO_GENERATE]


The **rand** variant of the command generates cryptographically secure
pseudo-random bytes starting with a seed picked using the system
entropy generator, whereas the **entropy** variant directly outputs
bytes from the system entropy pool.  With no arguments these command
generates a never ending stream of cryptographically secure random
bytes. For a non-negative integral argument **N**, this command
generates exactly **N** bytes of random data. By the system entropy
pool, we mean the best source of entropy on the given platform,
e.g. getrandom on recent Linux kernels, arc4random on openbsd etc.

A user *should* use the **rand** variant and should never even
consider using the **entropy** variant even if it *sounds* more
random.

The algorithm behind the **rand** command is essentially the same as
that of the **arc4random** call available on OpenBSD/NetBSD system. It
uses the chacha20 cipher to expand the seed (which is picked from the
system entropy pool) and stretches it into a stream of pseudo-random
bytes using the *Fast Key Erasure* technique as described in the blog
post <https://blog.cr.yp.to/20170723-random.html>. It is very likely
that the system **entropy** command also uses the same algorithm (at
least if you are on OpenBSD/NetBSD/Latest Linux) the seed for which
comes from known sources of randomness in the operating system. In
terms of quality, there is no reason to choose the **entropy**
variant.  The **rand** variant is often faster than the **entroy**
variant due to lesser system calls overhead.


Why then do we expose the **entropy** variant ? It is mainly to check
the quality of the entropy used in the raaz library using statistical
tests like die-harder. Such statistical tests _do not_ give any
assurance on the cryptographic safety of the generator. However, they
can often reveal silly mistakes in the code base (like forgetting to
seed).


## File checksums

**raaz** **checksum** [OPTIONS] *FILE1* *FILE2* ...

This command uses the message digest algorithm in raaz to
compute/verify file checksums. One can use these checksum command to
compute as well as verify the integrity of files. In *compute mode*,
the command prints one line in the format (DIGEST 2*SPACE FILE) for
each input file. The DIGEST is the base16 encoding of the
cryptographic hash of the contents of the file. For example,

```
$ raaz checksum /dev/null
786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce  /dev/null

```

In *computation mode*, a non-zero exist status indicates some error in
opening one of the input file.  In *verification mode*, **raaz**
returns a non-zero status if the checksum of a file does not match
with its associated input checksum. Thus, these commands can be used
to check the integrity of a set of files.


This command serves as a replacement for the common unix commands
sha512sum and sha256sum.


**Common options for all checksum commands**

**-c**, **\--check**
:    *Verify* the checksums present in the input file instead of compute
     the checksum of the arguments.

**-q**, **\--quiet**
:    While verifying do not print OK for successful checks. Only print failures.

**-s**, **\--status**
:    While verifying do not print anything. Only return the appropriate exit status.


## Library information

**raaz** **info**

Print various information regarding the raaz library
installation. This includes printing out the details of various
primitive implementations, entropy source, detected cpu capabilities
etc.
