#!/bin/bash

output_dir=(
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/png/output"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/jasper/output"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/mp4/output"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/jpeg/output"
)

binary_path=(
    "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/aflfast-install/bin/pngpixel"
    "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/aflfast-install/bin/jasper"
    "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/aflfast-install/bin/ffmpeg"
    "/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/aflfast-install/bin/djpeg"
)

afl_args=(
    "-m none -M aflfast-png-master"
    "-m none -M aflfast-jasper-master"
    "-m none -M aflfast-mp4-master"
    "-m none -M aflfast-jpeg-master"
)

binary_args=(
    "0 0 @@"
    "-f @@ -t jp2 -F /home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/jasperout.jpg -T jpg"
    "-i @@"
    "@@"
)

input_dir=(
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/png/input"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/jasper/input"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/mp4/input"
    "/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/jpeg/input"
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
            AFL_SKIP_CRASHES=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/dp/Documents/install/fuzzing/chunk-afl-evaluation/aflfast-install/lib timeout -s INT 2h /home/dp/Documents/fuzzing/aflfast/afl-fuzz -i ${input_dir[$i]} -o ${output_dir[$i]} ${afl_args[$i]} ${binary_path[$i]} ${binary_args[$i]}
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
