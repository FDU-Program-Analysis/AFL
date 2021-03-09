#-*- coding: UTF-8 -*- 
import matplotlib
matplotlib.use('Agg')
from matplotlib.font_manager import *
import matplotlib.pyplot as plt
myfont = FontProperties(fname='/usr/share/fonts/opentype/noto/NotoSerifCJK-Bold.ttc', weight="bold")
plt.rcParams['axes.unicode_minus']=False
import sys
reload(sys)
sys.setdefaultencoding("utf-8")

labels = ['WAV', 'JP2', 'MP4', 'PNG', 'JPEG']
true_positive = [2, 4, 0, 4, 10]
chunkfuzzer = [2, 6, 4, 6, 11]
x = range(len(true_positive))

rects1 = plt.bar(x=x, height=true_positive, width=0.4, alpha=0.8, color='red', label='ChunkFuzzer识别真阳性块数')
rects2 = plt.bar(x=[i + 0.4 for i in x], height=chunkfuzzer, width=0.4, color='blue', label='010 Editor识别块数')
plt.ylim(0, 15)

plt.xticks([index + 0.2 for index in x], labels)
plt.title("ChunkFuzzer块结构识别精确率", fontproperties=myfont)
plt.legend(prop=myfont, loc="upper left")

plt.savefig("true_positive_compare2.png",dpi=1080,format='png', bbox_inches='tight')
plt.show()
