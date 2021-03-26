#!/bin/sh

ARCH=i386-win32
GCC=i686-w64-mingw32-gcc
DST=../../static/$ARCH/sqlite3.o
DST2=../../../lib2/static/$ARCH/sqlite3.o

rm $DST
rm $DST2
rm sqlite3-$ARCH.o

echo
echo ---------------------------------------------------
echo Compiling for FPC on $ARCH using $GCC
$GCC -O2 -m32 -DSQLITE_NO_THREAD -DSQLITE_OMIT_LOCALTIME -DWIN32 -DNDEBUG -D_WINDOWS -c sqlite3mc.c -o sqlite3-$ARCH.o
# SQLITE_NO_THREAD and SQLITE_OMIT_LOCALTIME to allow proper linking
cp sqlite3-$ARCH.o $DST
cp sqlite3-$ARCH.o $DST2
