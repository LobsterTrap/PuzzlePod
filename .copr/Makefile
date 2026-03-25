# COPR make_srpm method: creates source tarball + SRPM from git checkout.
# COPR calls: make -f .copr/Makefile srpm outdir="<resultdir>" spec="<spec>"
#
# NOTE: The mock chroot does NOT have git installed. We read commit info
# directly from .git/ files and use tar (GNU) instead of git archive.
#
# The 'spec' variable is the absolute path to the spec file, set by COPR.
#
# We inject %global commit/shortcommit/commitdate into a copy of the spec
# so the values survive COPR re-running rpmbuild in the target chroot
# (where --define flags from this Makefile are not passed).

COMMIT = $(shell cat .git/$$(cat .git/HEAD | sed 's/ref: //') 2>/dev/null || cat .git/HEAD)
SHORTCOMMIT = $(shell echo $(COMMIT) | cut -c1-7)
COMMITDATE = $(shell date +%Y%m%d)
SOURCE_NAME = puzzlepod-$(COMMIT)

srpm:
	tar -czf $(outdir)/$(SOURCE_NAME).tar.gz \
		--transform 's,^\./,$(SOURCE_NAME)/,' \
		--transform 's,^\.,$(SOURCE_NAME),' \
		--exclude='./.git' \
		--exclude='./target' \
		.
	sed -e '1i %global commit $(COMMIT)' \
	    -e '1i %global shortcommit $(SHORTCOMMIT)' \
	    -e '1i %global commitdate $(COMMITDATE)' \
	    $(spec) > $(outdir)/puzzled.spec
	rpmbuild -bs $(outdir)/puzzled.spec \
		--define "_sourcedir $(outdir)" \
		--define "_srcrpmdir $(outdir)"

.PHONY: srpm
