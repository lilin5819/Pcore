#! /bin/sh
#
# build.sh
# Copyright (C) 2018 lilin <lilin@lilin-think>
#
# Distributed under terms of the MIT license.
#

[ -d build ] || mkdir build
#make -C build clean
cd build
make clean
cmake ..
make
cd ..
