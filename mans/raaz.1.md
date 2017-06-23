---
title: RAAZ(1) The Raaz Cryptographic Library | Version 0.2
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

**raaz** **rand** [BYTES_TO_GENERATE]


With no arguments this command generates a never ending stream of
cryptographically secure random bytes. For a non-negative integral
argument **N**, this command generates exactly **N** bytes of random
data.


## File checksums

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
