PYTHON?=	python3
TWINE?=		twine
GPG?=		gpg2
GPGSIGNKEY?=	0xB5D3397E

VERSION:=$(shell $(PYTHON) -c 'import acefile; print(acefile.__version__)')

SDIST=		dist/acefile-$(VERSION).tar.gz
SDISTSIG=	$(SDIST:=.asc)
APIDOC=		apidoc-acefile-$(VERSION).tar.bz2

all: test dist sign apidoc

apidoc:
	$(MAKE) -C apidoc all
	tar -c -v -y -f $(APIDOC) -C apidoc/_build/html _static index.html

dist: $(SDIST)

$(SDIST):
	$(PYTHON) setup.py sdist

sign: $(SDISTSIG)

$(SDISTSIG): $(SDIST)
	$(GPG) -u $(GPGSIGNKEY) --detach-sign -a $(SDIST)

upload: $(SDISTSIG)
	$(TWINE) upload $(SDIST) $(SDISTSIG)

doctest:
	$(PYTHON) acefile.py --doctest

test:
	$(PYTHON) setup.py test

build:
	$(PYTHON) setup.py build_ext --inplace

clean:
	$(MAKE) -C apidoc clean
	rm -rf apidoc-acefile-*.tar.bz2
	find . -depth -name '__pycache__' -type d -exec rm -r '{}' \;
	rm -rf acefile.egg-info
	rm -rf build *.so

todo:
	egrep -r 'XXX|TODO|FIXME' *.py

.PHONY: all apidoc dist sign upload doctest test build clean todo

