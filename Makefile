FIND_COMMAND = find . -name \*.py
SOURCE := $(shell $(FIND_COMMAND))

tags: TAGS.gz

TAGS.gz: TAGS
	gzip -f $^

.tag-source: $(SOURCE)
	$(FIND_COMMAND) -print > $@

TAGS: .tag-source
	ctags -e -o $@ -L $^ --extra=+f --python-kinds=-i

coverage: .coverage bin/coverage bin/nosetests
	bin/coverage html -d $@ --include='dream/**'

bin/nosetests:
	easy_install nose

bin/coverage:
	easy_install coverage

.coverage:
	nosetests --with-coverage

sdist:
	python setup.py sdist

clean:
	rm -rf TAGS TAGS.gz .tag-source .coverage coverage
