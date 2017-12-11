MAN_PAGES=raaz.1  # Which man pages to generate.
MAN_PAGES_GZ= $(addsuffix .gz, ${MAN_PAGES})
MAN_SOURCES= $(addsuffix .md, ${MAN_PAGES})

.PHONY: all clean

all: ${MAN_PAGES_GZ}
clean:
	rm -f ${MAN_PAGES} ${MAN_PAGES_GZ}

${MAN_PAGES_GZ}:%.gz:%
	gzip -f $<
${MAN_PAGES}:%:%.md
	pandoc -s  $< -t man -o $@
