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

labels = ['wavpack', 'jasper', 'ffmpeg', 'pngpixel', 'djpeg']
before_instu = [1, 1, 1, 1, 1]
after_instu = [549430 / 80834, 661674 / 100933, 49456781 / 10707971, 386215 / 69199, 589157 / 64629]
x = range(len(before_instu))

rects1 = plt.bar(x=x, height=before_instu, width=0.4, alpha=0.8, color='red', label='插桩前')
rects2 = plt.bar(x=[i + 0.4 for i in x], height=after_instu, width=0.4, color='blue', label='插桩后')
plt.ylim(0, 10)
plt.ylabel("指令数相对增长", fontproperties=myfont)

plt.xticks([index + 0.2 for index in x], labels)
plt.title("插桩前后指令数对比", fontproperties=myfont)
plt.legend(prop=myfont, loc="upper left")

plt.savefig("instu_compare.png",dpi=1080,format='png', bbox_inches='tight')
plt.show()
