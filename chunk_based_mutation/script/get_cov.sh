#!/bin/sh

# ../configure --disable-nls CFLAGS="-g -fprofile-arcs -ftest-coverage"

# cd ~/tests/jpeg-9a/obj-gcov && \
# find . -name '*.gcda'|xargs rm -f && \
# cd ./.libs && \
# find . -name '*.gcda'|xargs rm -f && \
# cd .. && \
# klee-replay ./djpeg ../obj-llvm/klee-last/*.ktest && \
# find . -name '*.gcda'|xargs gcov -a && \
# find . -name '*.gcov'|xargs grep -v '$$$$$:' | grep -c '\-block'

cd /home/dp/Documents/fuzzing/chunk-afl-evaluation/lib-src/gcov-lib/jpeg-9d && \
find . -name '*.gcda'|xargs rm -f && \
find /home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jpeg/output/afl-jpeg-no-dict-slave/queue -name "id:*" -exec /home/dp/Documents/install/fuzzing/chunk-afl-evaluation/gcov-install/bin/djpeg {} \; && \
find . -name '*.gcda'|xargs gcov -a && \
find . -name '*.gcov'|xargs grep -v '$$$$$:' | grep -c '\-block'

#-search=random-path
#djpeg(jpeg-v9a):532

#ImageMagick from github,7.0.8-24  commit b5fd640a3ee8b3e25fe844848d9156e68e2df3e2
#imageMagick(no support):4175
#imageMagick(support jpeg+png,jpeg+png without source):
#	libjpeg.so.8.0.2 
#	libpng12.so.0.54.0
#	./utilities/magick.gcov : 32
#	./MagickCore/.libs/ :4091
#	./MagickWand/.libs :162
#	./coders/.libs/ : 211
#	./filters/.libs/ : 0
#imageMagick(zlib):
#	zlib from github v1.2.11
#	zlib: 436
#	.//utilities/magick.gcov : 32
#       ./MagickCore/.libs/ :3846
#	./MagickWand/.libs :187
#       ./coders/.libs/ : 148



#ImageMagick:7.0.8-23 -search=dfs
#ImageMagick + freetype 2.9.1 release:
#	freetype:0
#	ImageMagick:3893
#	/utilities/magick.c: 32
#	/MagickCore/: 3401
#	/MagickWand/: 187
#	/coders/: 305
#	/filters/: 0

#ImageMagick + zlib 1.2.11
#	zlib: 0
#	/utilities/magick.c: 32
#       /MagickCore/: 3408
#       /MagickWand/: 187
#       /coders/: 305
#       /filters/: 0

#ImageMagick + libxml2-2.9.9
#	libxml: 3
#	/utilities/magick.c: 32
#       /MagickCore/: 3398
#       /MagickWand/: 187
#       /coders/: 335
#       /filters/: 0

#ImageMagick + tiff-4.0.10
#	tiff: 0
#       /utilities/magick.c: 33
#       /MagickCore/: 3524
#       /MagickWand/: 303
#       /coders/: 322
#       /filters/: 0

#ImageMagick -default support
#       /utilities/magick.c: 32
#       /MagickCore/: 3398
#       /MagickWand/: 187
#       /coders/: 344
#       /filters/: 0
#--------------------------------------------------------------------
#
#s2e coverage
#Imagemagick+tiff
#       /utilities/magick.c: 32
#       /MagickCore/: 2662
#       /MagickWand/: 187
#       /coders/: 118
#       /filters/: 0
#	tiff:0

#Imagemagick+xml
#       /utilities/magick.c: 32
#       /MagickCore/: 2662
#       /MagickWand/: 187
#       /coders/: 131
#       /filters/: 0
#       xml:3

#Imagemagick+zlib
#       /utilities/magick.c: 32
#       /MagickCore/: 2671
#       /MagickWand/: 187
#       /coders/: 101
#       /filters/: 0
#       zlib: 0

#Imagemagick+freetype
#       /utilities/magick.c: 32
#       /MagickCore/: 2665
#       /MagickWand/: 187
#       /coders/: 101
#       /filters/: 0
#       freetype: 0


#ImageMagick -default support
#       /utilities/magick.c: 32
#       /MagickCore/: 2662
#       /MagickWand/: 187
#       /coders/: 140
#       /filters/: 0

#ImageMagick -non-disable  AFL
#	total:5325
#	/utilities/magick.c: 32
#	/MagickCore/: 4348
#       /MagickWand/: 282
#       /coders/: 663
#       /filters/: 0

#ImageMagic  jpeg-png  AFL
#	total:4211
#	/utilities/magick.c:32
#       /MagickCore/:3965
#       /MagickWand/:69
#       /coders/:145
#	/filters/: 0

