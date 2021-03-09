#!/bin/bash

target=(
"djpeg"
"pngpixel"
"ffmpeg"
"opj_decompress"
"wavpack"
)

args=(
"@@"
"0 0 @@"
"-i @@"
"-i @@ -o out.png"
"-y @@"
)

input=(
"/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jpeg/input/not_kitty.jpg"
"0 0 /home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/png/input/not_kitty.png"
"-i /home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/mp4/input/small_movie.mp4"
"-i /home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jp2/input/not_kitty.jp2 -o out.png"
"/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/wav/input/44b.wav"
)

i=0
while true; do
	#read up rest </proc/uptime; t1="${up%.*}${up#*.}"
	t1=$(($(date +%s%N)/1000000))
	/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/afl-install/bin/${target[$i]} ${input[$i]}
	#read up rest </proc/uptime; t2="${up%.*}${up#*.}"
	t2=$(($(date +%s%N)/1000000))
	millisec=$(((t2-t1) ))
	echo ${target[$i]},$millisec >> runtime
	i=`expr $i + 1`
	if [ $i -eq 5 ]
	then
		break
	fi
done
