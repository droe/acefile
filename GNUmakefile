PYTHON?=	python3
TWINE?=		twine
GPG?=		gpg2
GPGSIGNKEY?=	0xB5D3397E

VERSION:=$(shell $(PYTHON) -c 'import acefile; print(acefile.__version__)')

SDIST=		dist/acefile-$(VERSION).tar.gz
SDISTSIG=	$(SDIST:=.asc)

all: dist sign

apidoc:
	$(MAKE) -C apidoc all

dist: $(SDIST)

$(SDIST):
	$(PYTHON) setup.py sdist

sign: $(SDISTSIG)

$(SDISTSIG): $(SDIST)
	$(GPG) -u $(GPGSIGNKEY) --detach-sign -a $(SDIST)

upload: $(SDISTSIG)
	$(TWINE) upload $(SDIST) $(SDISTSIG)

test:
	$(PYTHON) acefile.py --doctest

clean:
	$(MAKE) -C apidoc clean
	find . -depth -name '__pycache__' -type d -exec rm -r '{}' \;
	rm -rf acefile.egg-info

todo:
	egrep -r 'XXX|TODO|FIXME' *.py

.PHONY: all apidoc dist sign upload test clean todo

