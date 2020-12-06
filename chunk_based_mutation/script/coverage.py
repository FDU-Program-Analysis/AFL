import os
import subprocess
import time

def get_all_inputs():
    list = []
    for root, dirs, files in os.walk("/home/dp/fuzzing/chunk-afl-evaluation/imagemagickoutput/afl-slave/queue"):
        for filename in files:
            list.append(os.path.join(root, filename))

    for root, dirs, files in os.walk("/home/dp/fuzzing/chunk-afl-evaluation/imagemagickoutput/afl-slave/hangs"):
        for filename in files:
            list.append(os.path.join(root, filename))

    for root, dirs, files in os.walk("/home/dp/fuzzing/chunk-afl-evaluation/imagemagickoutput/afl-master/queue"):
        for filename in files:
            list.append(os.path.join(root, filename))

    for root, dirs, files in os.walk("/home/dp/fuzzing/chunk-afl-evaluation/imagemagickoutput/afl-master/hangs"):
        for filename in files:
            list.append(os.path.join(root, filename))
    return list


basetime = os.path.getmtime(
    "/home/dp/fuzzing/chunk-afl-evaluation/imagemagickoutput/afl-master/queue/id:000005,src:000000,op:flip1,pos:0,+cov")

input_list = get_all_inputs()
dict = {}
os.chdir("/home/dp/fuzzing/chunk-afl-evaluation/libsrc/chunk-afl")
os.system("find . -name '*.gcda'|xargs rm -f")
index = 0
for input in input_list:
    index += 1
    if index == 10:
        break
    if (input.split(".")[-1] == "json"):
        continue
    os.system("/home/dp/install/fuzzing/chunk-afl-evaluation/chunk-afl-install/bin/identify -verbose " + input)
    
    os.system("lcov -c -o coverage.info -d .")
    file = open("coverage.info", "r")
    line = file.readline()
    cur_file = ""
    filetime = os.path.getmtime(input)
    m, s = divmod(filetime - basetime, 60)
    while line:
        parts = line.strip().split(":")
        if(parts[0] == "SF"):
            cur_file = parts[1]
            if not cur_file in dict:
                dict[cur_file] = {}
        if(parts[0] == "DA"):
            parts = parts[1].split(",")
            if(parts[1] != "0"):
                if not parts[0] in dict[cur_file]:
                    dict[cur_file][parts[0]] = int(m)
                else:
                    if(dict[cur_file][parts[0]] > int(m)):
                        dict[cur_file][parts[0]] = int(m)
        line = file.readline()
    file.close()

os.chdir("/home/dp/fuzzing/chunk-afl-evaluation/coverage")
cov_files_list = list(dict.keys())
cov_files = open("chunk-afl","w+")
cov_files_list.sort()
for file in cov_files_list:
    cov_lines_list = list(dict[file].keys())
    if(len(cov_lines_list) == 0):
        continue
    cov_lines_list.sort()
    cov_files.write(file + "\n")
    for line in cov_lines_list:
        cov_files.write(line + ":" + (str)(dict[file][line]) + ",")
    cov_files.write("\n")
