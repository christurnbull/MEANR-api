#!/bin/sh

eslint -c .eslintrc --fix src/

for f in $(find src/ -name '*.js'); do
  js-beautify -r -k -n -s 2 $f
done
