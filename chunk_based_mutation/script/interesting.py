#-*- coding: UTF-8 -*- 
import matplotlib
matplotlib.use('Agg')
from matplotlib.font_manager import *
import matplotlib.pyplot as plt
myfont = FontProperties(fname='/usr/share/fonts/opentype/noto/NotoSerifCJK-Bold.ttc')
plt.rcParams['axes.unicode_minus']=False
import sys
reload(sys)
sys.setdefaultencoding("utf-8")

def get_data(path):
    plot_file = open(path, "r")
    plot_file.readline()
    line = plot_file.readline().strip()
    time = []
    inputs = []
    while line:
        data = line.split(",")
        time.append((int)(data[0]))
        inputs.append((int)(data[3]))
        line = plot_file.readline().strip()
    start = time[0]
    for i in range(0, len(time)):
        time[i] = time[i] - start
    return time, inputs

afl_jpeg_time, afl_jpeg_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jpeg/output/afl-jpeg-no-dict-slave/plot_data")
afl_jpeg_dict_time, afl_jpeg_dict_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/jpeg/output-dict/afl-jpeg-with-dict-slave/plot_data")
chunk_jpeg_time, chunk_jpeg_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/jpeg/output-dict/chunk-afl-jpeg-withdict-slave/plot_data")
fast_jpeg_time, fast_jpeg_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/jpeg/output/aflfast-jpeg-slave/plot_data")
plus_jpeg_time, plus_jpeg_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/jpeg/output/aflplusplus-jpeg-slave/plot_data")

afl_jpeg_time_2h = []
afl_jpeg_inputs_2h = []
for i in range(0, len(afl_jpeg_time)):
    if(afl_jpeg_time[i] < 7000):
        afl_jpeg_time_2h.append(afl_jpeg_time[i])
        afl_jpeg_inputs_2h.append(afl_jpeg_inputs[i])
print(afl_jpeg_inputs_2h[-1])

chunk_jpeg_time_2h = []
chunk_jpeg_inputs_2h = []
for i in range(0, len(chunk_jpeg_time)):
    if(chunk_jpeg_time[i] < 7000):
        chunk_jpeg_time_2h.append(chunk_jpeg_time[i])
        chunk_jpeg_inputs_2h.append(chunk_jpeg_inputs[i])
print(chunk_jpeg_inputs_2h[-1])

afl_jpeg_dict_time_2h = []
afl_jpeg_dict_inputs_2h = []
for i in range(0, len(afl_jpeg_dict_time)):
    if(afl_jpeg_dict_time[i] < 7000):
        afl_jpeg_dict_time_2h.append(afl_jpeg_dict_time[i])
        afl_jpeg_dict_inputs_2h.append(afl_jpeg_dict_inputs[i])

print(afl_jpeg_dict_inputs_2h[-1])

fast_jpeg_time_2h = []
fast_jpeg_inputs_2h = []
for i in range(0, len(fast_jpeg_time)):
    if(fast_jpeg_time[i] < 7000):
        fast_jpeg_time_2h.append(fast_jpeg_time[i])
        fast_jpeg_inputs_2h.append(fast_jpeg_inputs[i])

print(fast_jpeg_inputs_2h[-1])

plus_jpeg_time_2h = []
plus_jpeg_inputs_2h = []
for i in range(0, len(plus_jpeg_time)):
    if(plus_jpeg_time[i] < 7000):
        plus_jpeg_time_2h.append(plus_jpeg_time[i])
        plus_jpeg_inputs_2h.append(plus_jpeg_inputs[i])

print(plus_jpeg_inputs_2h[-1])

afl_png_time, afl_png_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/png/output/afl-png-nodict-slave/plot_data")
afl_png_dict_time, afl_png_dict_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/png/output-dict/afl-png-withdict-slave/plot_data")
chunk_png_time, chunk_png_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/png/output-dict/chunk-afl-png-withdict-slave/plot_data")
fast_png_time, fast_png_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/png/output/aflfast-png-slave/plot_data")
plus_png_time, plus_png_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/png/output/aflplusplus-png-slave/plot_data")

afl_png_time_2h = []
afl_png_inputs_2h = []
for i in range(0, len(afl_png_time)):
    if(afl_png_time[i] < 7000):
        afl_png_time_2h.append(afl_png_time[i])
        afl_png_inputs_2h.append(afl_png_inputs[i])
print(afl_png_inputs_2h[-1])

chunk_png_time_2h = []
chunk_png_inputs_2h = []
for i in range(0, len(chunk_png_time)):
    if(chunk_png_time[i] < 7000):
        chunk_png_time_2h.append(chunk_png_time[i])
        chunk_png_inputs_2h.append(chunk_png_inputs[i])
print(chunk_png_inputs_2h[-1])

afl_png_dict_time_2h = []
afl_png_dict_inputs_2h = []
for i in range(0, len(afl_png_dict_time)):
    if(afl_png_dict_time[i] < 7000):
        afl_png_dict_time_2h.append(afl_png_dict_time[i])
        afl_png_dict_inputs_2h.append(afl_png_dict_inputs[i])

print(afl_png_dict_inputs_2h[-1])

fast_png_time_2h = []
fast_png_inputs_2h = []
for i in range(0, len(fast_png_time)):
    if(fast_png_time[i] < 7000):
        fast_png_time_2h.append(fast_png_time[i])
        fast_png_inputs_2h.append(fast_png_inputs[i])

print(fast_png_inputs_2h[-1])

plus_png_time_2h = []
plus_png_inputs_2h = []
for i in range(0, len(plus_png_time)):
    if(plus_png_time[i] < 7000):
        plus_png_time_2h.append(plus_png_time[i])
        plus_png_inputs_2h.append(plus_png_inputs[i])

print(plus_png_inputs_2h[-1])

afl_mp4_time, afl_mp4_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/mp4/output/afl-mp4-nodict-slave/plot_data")
afl_mp4_dict_time, afl_mp4_dict_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/afl/mp4/output-dict/afl-mp4-withdict-slave/plot_data")
chunk_mp4_time, chunk_mp4_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/mp4/output-dict/chunk-afl-mp4-withdict-slave/plot_data")
fast_mp4_time, fast_mp4_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/mp4/output/aflfast-mp4-slave/plot_data")
plus_mp4_time, plus_mp4_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/mp4/output/aflplusplus-mp4-slave/plot_data")

afl_mp4_time_2h = []
afl_mp4_inputs_2h = []
for i in range(0, len(afl_mp4_time)):
    if(afl_mp4_time[i] < 7000):
        afl_mp4_time_2h.append(afl_mp4_time[i])
        afl_mp4_inputs_2h.append(afl_mp4_inputs[i])
print(afl_mp4_inputs_2h[-1])

chunk_mp4_time_2h = []
chunk_mp4_inputs_2h = []
for i in range(0, len(chunk_mp4_time)):
    if(chunk_mp4_time[i] < 7000):
        chunk_mp4_time_2h.append(chunk_mp4_time[i])
        chunk_mp4_inputs_2h.append(chunk_mp4_inputs[i])
print(chunk_mp4_inputs_2h[-1])

afl_mp4_dict_time_2h = []
afl_mp4_dict_inputs_2h = []
for i in range(0, len(afl_mp4_dict_time)):
    if(afl_mp4_dict_time[i] < 7000):
        afl_mp4_dict_time_2h.append(afl_mp4_dict_time[i])
        afl_mp4_dict_inputs_2h.append(afl_mp4_dict_inputs[i])

print(afl_mp4_dict_inputs_2h[-1])

fast_mp4_time_2h = []
fast_mp4_inputs_2h = []
for i in range(0, len(fast_mp4_time)):
    if(fast_mp4_time[i] < 7000):
        fast_mp4_time_2h.append(fast_mp4_time[i])
        fast_mp4_inputs_2h.append(fast_mp4_inputs[i])

print(fast_mp4_inputs_2h[-1])

plus_mp4_time_2h = []
plus_mp4_inputs_2h = []
for i in range(0, len(plus_mp4_time)):
    if(plus_mp4_time[i] < 7000):
        plus_mp4_time_2h.append(plus_mp4_time[i])
        plus_mp4_inputs_2h.append(plus_mp4_inputs[i])

print(plus_mp4_inputs_2h[-1])

afl_jasper_time, afl_jasper_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl/chunk_based_mutation/jpeg/jasper_afl_plot_data.data")
afl_jasper_dict_time, afl_jasper_dict_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl/chunk_based_mutation/jpeg/jasper-dictplot_data.data")
chunk_jasper_time, chunk_jasper_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/chunk-afl/jasper/output/chunk-afl-jasper-slave/plot_data")
fast_jasper_time, fast_jasper_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflfast/jasper/output/aflfast-jasper-slave/plot_data")
plus_jasper_time, plus_jasper_inputs = get_data("/home/dp/Documents/fuzzing/chunk-afl-evaluation/aflplusplus/jasper/output/aflplusplus-jasper-slave/plot_data")

afl_jasper_time_2h = []
afl_jasper_inputs_2h = []
for i in range(0, len(afl_jasper_time)):
    if(afl_jasper_time[i] < 7000):
        afl_jasper_time_2h.append(afl_jasper_time[i])
        afl_jasper_inputs_2h.append(afl_jasper_inputs[i])
print(afl_jasper_inputs_2h[-1])

chunk_jasper_time_2h = []
chunk_jasper_inputs_2h = []
for i in range(0, len(chunk_jasper_time)):
    if(chunk_jasper_time[i] < 7000):
        chunk_jasper_time_2h.append(chunk_jasper_time[i])
        chunk_jasper_inputs_2h.append(chunk_jasper_inputs[i])
print(chunk_jasper_inputs_2h[-1])

afl_jasper_dict_time_2h = []
afl_jasper_dict_inputs_2h = []
for i in range(0, len(afl_jasper_dict_time)):
    if(afl_jasper_dict_time[i] < 7000):
        afl_jasper_dict_time_2h.append(afl_jasper_dict_time[i])
        afl_jasper_dict_inputs_2h.append(afl_jasper_dict_inputs[i])

print(afl_jasper_dict_inputs_2h[-1])

fast_jasper_time_2h = []
fast_jasper_inputs_2h = []
for i in range(0, len(fast_jasper_time)):
    if(fast_jasper_time[i] < 7000):
        fast_jasper_time_2h.append(fast_jasper_time[i])
        fast_jasper_inputs_2h.append(fast_jasper_inputs[i])

print(fast_jasper_inputs_2h[-1])

plus_jasper_time_2h = []
plus_jasper_inputs_2h = []
for i in range(0, len(plus_jasper_time)):
    if(plus_jasper_time[i] < 7000):
        plus_jasper_time_2h.append(plus_jasper_time[i])
        plus_jasper_inputs_2h.append(plus_jasper_inputs[i])

print(plus_jasper_inputs_2h[-1])



# plt.xlabel("时间/秒", fontproperties=myfont)
# plt.ylabel("输入生成数量", FontProperties=myfont)

plt.subplot(2,2,1)

jpeg_l3, = plt.plot(chunk_jpeg_time_2h, chunk_jpeg_inputs_2h, color='red', label='ChunkFuzzer')
jpeg_l1, = plt.plot(afl_jpeg_time_2h, afl_jpeg_inputs_2h, color="blue", label='AFL')
jpeg_l2, = plt.plot(afl_jpeg_dict_time_2h, afl_jpeg_dict_inputs_2h, color="green", label='AFL-dict')
jpeg_l4, = plt.plot(fast_jpeg_time_2h, fast_jpeg_inputs_2h, color="gray", label='AFLFast')
jpeg_l5, = plt.plot(plus_jpeg_time_2h, plus_jpeg_inputs_2h, color='purple', label='AFL++')

# plt.legend(loc = 'down right')

# plt.title("djpeg")
# plt.savefig("jpeg_inputs_time.png",dpi=1080,format='png', bbox_inches='tight')
# plt.title("pngpixel")
# plt.savefig("png_inputs_time.png" ,dpi=1080,format='png', bbox_inches='tight')
# plt.title("ffmepg")
# plt.savefig("mp4_inputs_time.png",dpi=1080,format='png', bbox_inches='tight')
plt.title("djpeg")

plt.yticks(range(500, 5000, 500))
plt.tick_params(labelsize=8)

plt.subplot(2,2,2)
png_l3, = plt.plot(chunk_png_time_2h, chunk_png_inputs_2h, color='red', label='ChunkFuzzer')
png_l1, = plt.plot(afl_png_time_2h, afl_png_inputs_2h, color="blue", label='AFL')
png_l2, = plt.plot(afl_png_dict_time_2h, afl_png_dict_inputs_2h, color="green", label='AFL-dict')
png_l4, = plt.plot(fast_png_time_2h, fast_png_inputs_2h, color="gray", label='AFLFast')
png_l5, = plt.plot(plus_png_time_2h, plus_png_inputs_2h, color='purple', label='AFL++')
plt.title("pngpixel")
plt.yticks(range(100,800,100),())
plt.tick_params(labelsize=8)
ax = plt.gca() 
ax2 = ax.twinx()
ax2.set_yticks(range(100, 800, 100))
plt.tick_params(labelsize=8)


plt.subplot(2,2,3)
mp4_l3, = plt.plot(chunk_mp4_time_2h, chunk_mp4_inputs_2h, color='red', label='ChunkFuzzer')
mp4_l1, = plt.plot(afl_mp4_time_2h, afl_mp4_inputs_2h, color="blue", label='AFL')
mp4_l2, = plt.plot(afl_mp4_dict_time_2h, afl_mp4_dict_inputs_2h, color="green", label='AFL-dict')
mp4_l4, = plt.plot(fast_mp4_time_2h, fast_mp4_inputs_2h, color="gray", label='AFLFast')
mp4_l5, = plt.plot(plus_mp4_time_2h, plus_mp4_inputs_2h, color='purple', label='AFL++')
plt.title("ffmpeg")
plt.yticks(range(2000, 17000, 2000))
plt.tick_params(labelsize=8)

plt.subplot(2,2,4)
jasper_l3, = plt.plot(chunk_jasper_time_2h, chunk_jasper_inputs_2h, color='red', label='ChunkFuzzer')
jasper_l1, = plt.plot(afl_jasper_time_2h, afl_jasper_inputs_2h, color="blue", label='AFL')
jasper_l2, = plt.plot(afl_jasper_dict_time_2h, afl_jasper_dict_inputs_2h, color="green", label='AFL-dict')
jasper_l4, = plt.plot(fast_jasper_time_2h, fast_jasper_inputs_2h, color="gray", label='AFLFast')
jasper_l5, = plt.plot(plus_jasper_time_2h, plus_jasper_inputs_2h, color='purple', label='AFL++')
plt.title("jasper")
plt.legend(bbox_to_anchor=(0, -0.15), loc=9, borderaxespad=0, ncol=5, frameon=False)
plt.yticks(range(400,4000,400),())
plt.tick_params(labelsize=8)
ax = plt.gca() 
ax2 = ax.twinx()
ax2.set_yticks(range(400, 4000, 400))
plt.tick_params(labelsize=8)


plt.tight_layout()


plt.savefig("jasper_inputs_time.png",dpi=1080,format='png', bbox_inches='tight')
plt.show()