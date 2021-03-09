#!/bin/bash

output_dir=(
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/jasper/output"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/mp4/output"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/png/output"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/jpeg/output"
)

binary_path=(
    "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/aflplusplus-install/bin/jasper"
    "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/aflplusplus-install/bin/ffmpeg"
    "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/aflplusplus-install/bin/pngpixel"
    "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/aflplusplus-install/bin/djpeg"
)

afl_args=(
    "-m none -S aflplusplus-jasper-slave"
    "-m none -S aflplusplus-mp4-slave"
    "-m none -S aflplusplus-png-slave"
    "-m none -S aflplusplus-jpeg-slave"
)

binary_args=(
    "-f @@ -t jp2 -F /home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/jasperout.jpg -T jpg"
    "-i @@"
    "0 0 @@"
    "@@"
)

input_dir=(
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/jasper/input"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/mp4/input"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/png/input"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/jpeg/input"
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
            AFL_SKIP_CRASHES=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/aflplusplus-install/lib timeout -s INT 2h /home/dp/Documents/fuzzing/AFLplusplus/afl-fuzz -i ${input_dir[$i]} -o ${output_dir[$i]} ${afl_args[$i]} ${binary_path[$i]} ${binary_args[$i]}
            i=`expr $i + 1`
        # fi
    fi
    if [ $i -eq 4 ]
    then
        echo "break" >> log
        echo `date` >> log
        break
    fi
done
