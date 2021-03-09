#!/bin/bash


output_dir=(
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/png/output"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/png/output-dict"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jp2/output"
"/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jp2/output-dict"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/mp3/output"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/wav/output"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/png/output-dict"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/jpeg/output-dict"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/mp4/output-dict"
)

binary_path=(
# "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/afl-install/bin/pngpixel"
# "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/afl-install/bin/pngpixel"
# "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/afl-install/bin/opj_decompress"
"/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/afl-install/bin/opj_decompress"
# "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/afl-install/bin/mpg321"
# "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/afl-install/bin/wavpack"

# "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/chunk-afl-install/bin/pngpixel"
# "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/chunk-afl-install/bin/djpeg"
# "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/chunk-afl-install/bin/ffmpeg"
)

afl_args=(
# "-m none -M afl-png-nodict-master"
# "-m none -M afl-png-withdict-master -x /home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/png/dict/png.dict"
# "-m none -M afl-jp2-nodict-master"
"-m none -M afl-jp2-withdict-master -x /home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jp2/dict/jp2.dict"
# "-m none -M afl-mp3-nodict-master"
# "-m none -M afl-wav-nodict-master"
# "-m none -M chunk-afl-png-withdict-master -x /home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/png/dict/png.dict"
# "-m none -M chunk-afl-jpeg-withdict-master -x /home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/jpeg/dict/jpeg.dict"
# "-m none -M chunk-afl-mp4-withdict-master -x /home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/mp4/dict/mp4.dict"
)

binary_args=(
# "0 0 @@"
# "0 0 @@"
# "-i @@ -o /home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jp2/out.png"
"-i @@ -o /home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jp2/out.png"
# "--stdout @@"
# "-y @@ -o /home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/wav/out-dir"
# "0 0 @@"
# "@@"
# "-i @@"
)

input_dir=(
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/png/input"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/png/input"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jp2/input"
"/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jp2/input"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/mp3/input"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/wav/input"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/png/input"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/jpeg/input"
# "/home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/mp4/input"
)

i=0
while true; do
    sleep 10
    echo "sleep"
    compile=`ps -ef|grep dp|grep clang |grep -v dp |wc -l`
    if [ $compile -eq 0 ]
    then
        # count=`ps -ef|grep jordan|grep afl-fuzz |grep -v grep |wc -l`
        # if [ $count -eq 0 ]
        # then
            date >> log
            echo ${log_dir[$i]},${binary_path[$i]}, ${binary_args[$i]}, ${input_dir[$i]} >> log
            #cd ${log_dir[$i]}
            echo AFL_SKIP_CRASHES=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/chunk-afl-install/lib timeout -s INT 6h /home/dp/Documents/install/fuzzing/chunk-afl-evaluation/chunk-afl-install/bin/afl-fuzz -i ${input_dir[$i]} -o ${output_dir[$i]} ${afl_args[$i]} ${binary_path[$i]} ${binary_args[$i]}
            i=`expr $i + 1`
        # fi
    fi
    if [ $i -eq 1 ]
    then
        echo "break" >> log
        echo `date` >> log
        break
    fi
done
