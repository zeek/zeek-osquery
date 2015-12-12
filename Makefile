
BUILD=build
REPO=`basename \`git config --get remote.origin.url | sed 's/^[^:]*://g'\``
VERSION=$(REPO)-`cat VERSION`

all: configured
	$(MAKE) -C $(BUILD) $@

install: configured all
	$(MAKE) -C $(BUILD) $@

test: configured all
	CTEST_OUTPUT_ON_FAILURE=1 $(MAKE) -C $(BUILD) $@

clean: configured
	$(MAKE) -C $(BUILD) $@

distclean:
	rm -rf $(BUILD)

configured:
	@test -d $(BUILD) || ( echo "Error: No build/ directory found. Did you run configure?" && exit 1 )
	@test -e $(BUILD)/Makefile || ( echo "Error: No build/Makefile found. Did you run configure?" && exit 1 )

.PHONY : all install test clean distclean configured
