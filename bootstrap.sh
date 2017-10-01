#!/bin/sh
git submodule init
git submodule update

cp sefcontext-parser/sefcontext_parser/sefcontext_parser.py SeUtils/
