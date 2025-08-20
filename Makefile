JSDEPLOY = $(DESTDIR)/js
JSCOMPILER ?= ./node_modules/terser/bin/terser

JSOPTIONS = --mangle reserved=['FormData','Ext','Zarafa','container','settings','properties','languages','serverconfig','user','version','urlActionData','console','Tokenizr','module','define','global','require','proxy','_','dgettext','dngettext','dnpgettext','ngettext','pgettext','onResize','tinymce','resizeLoginBox','userManager','DOMPurify','PDFJS','odf','L','GeoSearch'] \
            --compress ecma=2015,computed_props=false

$(DESTDIR)/%: %
	mkdir -p $$(dirname $@)
	cp $< $@

MSGFMT ?= msgfmt

JSFILES = js/PasskeyPlugin.js \
          js/data/Configuration.js \
          js/data/ResponseHandler.js \
          js/settings/Category.js \
          js/settings/GeneralSettingsWidget.js

COPYFILES = manifest.xml config.php \
	$(wildcard resources/css/*.css) \
	$(wildcard resources/icons/*.png) \
	$(shell find php/ -type f \! -name '.*' -not -path '*/tests/*' -not -path '*/examples/*' -not -path '*/vendor/bin/*' -not -path '*/.github/*' -not -iname '*.py' -not -iname 'naturalselection')

COPYFILESDEST = $(addprefix $(DESTDIR)/, $(COPYFILES))

all: $(COPYFILESDEST) $(JSDEPLOY)/passkey.js

$(JSDEPLOY)/passkey.js: $(JSFILES)
	mkdir -p $(DESTDIR)/js
	cat $(JSFILES) > $(@:.js=-debug.js)
	$(JSCOMPILER) $(@:.js=-debug.js) --output $@ \
		--source-map "url='$(shell basename $@.map)'" \
	        $(JSOPTIONS)

clean:
	rm -rf $(DESTDIR)

install: all

.PHONY: all clean install
