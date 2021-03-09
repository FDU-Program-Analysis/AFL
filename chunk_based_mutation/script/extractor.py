import re

def extractor(path):
    file = open(path, "r")
    line = file.readline()
    while line:
        p = re.compile(r'\'.*?\'')
        list = re.findall(p, line)
        idList = []
        for item in list:
            idList.append(item.split("'")[1])
        # if(len(idList) != 0):
        #     print("id=\"" + ''.join(idList) + "\"") 
        line = file.readline()

# extractor("/home/dp/Documents/fuzzing/chunk-afl/chunk_based_mutation/script/mov.c")

file = open("/home/dp/Documents/fuzzing/chunk-afl/chunk_based_mutation/script/mp4id.dict", "r")
line = file.readline().strip()
list = []
while line:
    if line not in list:
        list.append(line)
    line = file.readline().strip()
list.sort()
for item in list:
    print(item)