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

labels = ['wav', 'jp2', 'mp4', 'png', 'jpeg']

precision = [100, 66.67, 0, 90.91, 64.85]
x = range(len(precision))

plt.bar(range(len(precision)), precision, color='blue')
plt.title("块结构识别准确率", fontproperties=myfont)
plt.yticks(range(10, 110, 10))

plt.xticks([index for index in x], labels)

plt.savefig("precision.png",dpi=1080,format='png', bbox_inches='tight')
plt.show()
