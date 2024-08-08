#!/bin/bash

pwd
echo "make sure you are running in a directory with only xml files, if not press ^C"
read
for i in $(ls); do
    python3 ../parser.py $i;
done