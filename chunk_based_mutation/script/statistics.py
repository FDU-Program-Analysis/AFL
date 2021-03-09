# import matplotlib.pyplot as plt


def statistics(path):
    coverage = open(path, "r")
    fileName = coverage.readline().strip()
    totalLine = 0
    times = {}
    fileLines = {}
    timeFileLine = {}
    while fileName:
        fileLines[fileName] = []
        line = coverage.readline().strip()
        lines = line.split(",")
        totalLine += len(lines) - 1
        for line in lines:
            if line == "":
                continue
            fileLines[fileName].append((int)(line.split(":")[0]))
            time = (int)(line.split(":")[1])
            if not time in timeFileLine:
                timeFileLine[time] = {}
            if not fileName in timeFileLine[time]:
                timeFileLine[time][fileName] = []
            timeFileLine[time][fileName].append((int)(line.split(":")[0]))
            if time in times:
                times[time] += 1
            else:
                times[time] = 1
        fileName = coverage.readline().strip()
    times = sorted(times.items(), reverse = False)
    coverage.close()
    return totalLine, times, fileLines

def drow():
    totalLine, times, fileLines = statistics("/home/dp/Documents/fuzzing/chunk-afl-evaluation/coverage/chunk-afl")
    aflx = []
    afly = []
    aflx.append(times[0][0])
    afly.append(times[0][1])
    for i in range(1, len(times)):
        aflx.append(times[i][0])
        afly.append(times[i][1] + afly[-1])
    for i in range(len(aflx)):
        print((str)(aflx[i]) + ":" +(str)(afly[i]))
    # plt.plot(x, y)
    # plt.show()

def analysis():
    totalLine, times, aflFileLines = statistics("/home/dp/Documents/fuzzing/chunk-afl-evaluation/coverage/ffmpeg/afl")
    print(totalLine)
    totalLine, times, chunkFileLines = statistics("/home/dp/Documents/fuzzing/chunk-afl-evaluation/coverage/ffmpeg/chunk")
    print(totalLine)
    aflMore = {}
    chunkMore = {}
    for file in aflFileLines:
        aflLines = aflFileLines[file]
        chunkFile = file.replace("afl", "chunk-afl", 1)
        if(chunkFile in chunkFileLines.keys()):
            chunkLines = chunkFileLines[chunkFile]
            assert file.replace("afl", "", 1) == chunkFile.replace("chunk-afl", "", 1)
            inter = list(set(aflLines) & set(chunkLines))
            aflMore[file] = list(set(aflLines) - set(inter))
            if(len(aflMore[file]) == 0):
                aflMore.pop(file)
            chunkMore[file] = list(set(chunkLines) - set(inter))
            if(len(chunkMore[file]) == 0):
                chunkMore.pop(file)
        else:
            aflMore[file] = aflLines
    for file in chunkFileLines:
        aflFile = file.replace("chunk-afl", "afl", 1)
        if(aflFile in aflFileLines.keys()):
            continue
        else:
            chunkMore[file] = chunkFileLines[file]
    aflMoreFile = open("/home/dp/Documents/fuzzing/chunk-afl-evaluation/coverage/ffmpeg/aflMore", "w")
    chunkMoreFile = open("/home/dp/Documents/fuzzing/chunk-afl-evaluation/coverage/ffmpeg/chunkMore", "w")

    aflNum = 0
    for file in sorted(aflMore):
        aflMoreFile.write(file + "\n")
        aflMore[file].sort()
        for line in aflMore[file]:
            aflMoreFile.write(str(line) + ",")
            aflNum += 1
        aflMoreFile.write("\n")
    
    chunkNum = 0
    for file in sorted(chunkMore):
        chunkMoreFile.write(file + "\n")
        chunkMore[file].sort()
        for line in chunkMore[file]:
            chunkMoreFile.write(str(line) + ",")
            chunkNum += 1
        chunkMoreFile.write("\n")

    print(chunkNum)
    print(aflNum)

analysis()
# totalLine, times, fileLines = statistics("/home/dp/Documents/fuzzing/chunk-afl-evaluation/coverage/chunk-afl")
# print(times)
#drow()
# statistics("/home/dp/Documents/fuzzing/chunk-afl-evaluation/coverage/chunk-afl")