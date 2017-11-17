---
title: RAAZ(1) The Raaz Cryptographic Library | Version 0.3
author: Piyush P Kurur
date: June 22, 2017
---

# NAME

raaz - Command line tool for the Raaz cryptographic library.

# SYNOPSIS

**raaz** **[-v|--version]**

**raaz** **[COMMAND]** **[COMMAND_OPTIONS]** **[ARGUMENTS]**


# DESCRIPTION

Raaz is a cryptographic library for the Haskell programming
language. One of the important design goal is to use the type system
of Haskell to catch various bugs like buffer overflows and timing
attacks at compile time. Thus, Raaz is meant to be used as
cryptographic library for applications written in Haskell.
Nonetheless, we expose some of the implemented primitives using the
program **raaz** for use in shell scripts.

# OPTIONS AND SUB-COMMANDS


The program **raaz** exposes the cryptographic primitives as
sub-commands. With no sub-commands **raaz** understands the following
options

**-h**, **--help**
:    Display help message. This option is supported by sub-commands as well
     in which case it displays the brief help of that sub-command.

**-v**, **--version**
:    Display the version of the underlying raaz library

The sub-commands of raaz falls in the following categories.

## Randomness

**raaz** **rand**    [BYTES_TO_GENERATE]

**raaz** **entropy** [BYTES_TO_GENERATE]

With no arguments these command generates a never ending stream of
cryptographically secure random bytes. For a non-negative integral
argument **N**, this command generates exactly **N** bytes of random
data.

The essential difference in these two variants is this: The **rand**
variant of the command generates cryptographically secure
pseudo-random bytes starting with a seed picked using the system
entropy generator, whereas the **entropy** variant directly outputs
bytes from the system entropy pool. By the system entropy pool, we
mean the best source of entropy on the given platform, e.g. getrandom
on recent Linux kernels, arc4random on openbsd etc.

Which of these variants should one prefer? Note that essentially all
sources of entropy are ultimately pseudo-random and so is the source
behind the **entropy** command. The algorithm behind the **raaz rand**
command is essentially the same as that of the arc4random call
available on OpenBSD/NetBSD system. There is *no* reason whatsoever to
prefer **entropy** over **rand** just because it sounds more random;
in fact **entropy** is almost always slower than the **rand** variant
due to overheads of system calls. A user _should_ therefore use the
**rand** variant. Why then provide the **entropy** variant? It is
mainly to check the quality of the system entropy pool using
statistical tests like die-harder. Such statistical __do not__ give
any assurance on the cryptographic safety of the generator. They
merely act as sanity checks against silly mistakes in the raaz code
base.

The **raaz rand** command uses the chacha20 cipher to expand the
starting stream into a stream of pseudo-random bytes. It uses the
*Fast Key Erasure* technique as described in the blog post
<https://blog.cr.yp.to/20170723-random.html>.

## File checksums

**raaz** **blake2bsum** [OPTIONS] *FILE1* *FILE2* ...

**raaz** **blake2ssum** [OPTIONS] *FILE1* *FILE2* ...

**raaz** **sha512sum** [OPTIONS] *FILE1* *FILE2* ...

**raaz** **sha256sum** [OPTIONS] *FILE1* *FILE2* ...

Use the above checksum commands to compute/verify file checksums.  All
these commands take the same set of options. One can use these
checksum commands to compute as well as verify the integrity of
files. In *compute mode*, the command prints one line in the format
(DIGEST 2*SPACE FILE) for each input file. The DIGEST is the base16
encoding of the cryptographic hash of the contents of the file. For
example,

```
$ raaz sha256sum /dev/null
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /dev/null

$ raaz blake2ssum /dev/null
69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9  /dev/null
```

In *computation mode*, a non-zero exist status indicates some error in
opening one of the input file.  In *verification mode*, **raaz**
returns a non-zero status if the checksum of a file does not match
with its associated input checksum. Thus, these commands can be used
to check the integrity of a set of files.


These commands provide an alternative to the common unix commands
sha512sum and sha256sum. Therefore, checksums computed by one of these
programs can be verified by **raaz** with the appropriate sub-command
(and vice-versa).


**Common options for all checksum commands**

**-c**, **--check**
:    *Verify* the checksums present in the input file instead of compute
     the checksum of the arguments.

**-q**, **--quiet**
:    While verifying do not print OK for successful checks. Only print failures.

**-s**, **--status**
:    While verifying do not print anything. Only return the appropriate exit status.


## Library information

**raaz** **info**

Print various information regarding the raaz library
installation. This includes printing out the details of various
primitive implementations, entropy source, detected cpu capabilities
etc.
