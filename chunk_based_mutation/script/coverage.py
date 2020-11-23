import os
import subprocess

def get_all_inputs():
    list = []
    for root, dirs, files in os.walk("/home/dp/imagemagickoutput-hybrid/chunk-afl-slave/queue"):
        for filename in files:
            list.append(os.path.join(root, filename))
    return list

input_list = get_all_inputs()
dict = {}
os.chdir("/home/dp/ImageMagick-test-afl")
os.system("find . -name '*.gcda'|xargs rm -f")
for input in input_list:
    if (input.split(".")[-1] == "json"):
        continue
    os.system("/home/dp/Documents/temp/install/bin/identify -verbose " + input)
    os.system("lcov -c -o coverage.info -d .")
    file = open("coverage.info", "r")
    line = file.readline()
    cur_file = ""
    while line:
        str = line.strip().split(":")
        if(str[0] == "SF"):
            cur_file = str[1]
            if not cur_file in dict:
                dict[cur_file] = {}
        if(str[0] == "DA"):
            str = str[1].split(",")
            if(str[1] != "0"):
                if not str[0] in dict[cur_file]:
                    dict[cur_file][str[0]] = int(str[1])
                else:
                    dict[cur_file][str[0]] += int(str[1])
        line = file.readline()
    file.close()

os.chdir("/home/dp/coverage")
cov_files_list = list(dict.keys())
cov_files = open("hybrid-chunk-afl-files","w+")
cov_files_list.sort()
for file in cov_files_list:
    cov_lines_list = list(dict[file].keys())
    if(len(cov_lines_list) == 0):
        continue
    cov_lines_list.sort()
    cov_files.write(file + "\n")
    for line in cov_lines_list:
        cov_files.write(line + ",")
    cov_files.write("\n")
