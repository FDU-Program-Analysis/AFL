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

jpeg = [39.5, 39.5, 39.5, 39.4, 38.9]
plt.bar(range(len(jpeg)), jpeg, color=['red', 'blue', 'green', 'grey', 'purple'])
plt.title("djpeg")
plt.yticks(range(10, 60, 5))

png = [9.7, 12.5, 13.7, 9.5, 9.3]
plt.bar(range(len(png)), png, color=['red', 'blue', 'green', 'grey', 'purple'])
plt.title("pngpixel")
plt.yticks(range(1, 15, 1))

ffmpeg = [7.8, 8.1, 8.4, 7.3, 7.4]
plt.bar(range(len(ffmpeg)), ffmpeg, color=['red', 'blue', 'green', 'grey', 'purple'])
plt.title("ffmpeg")
plt.yticks(range(1, 10, 1))

ffmpeg = [38.9, 38.9, 40.6, 39.4, 7.4]
plt.bar(range(len(ffmpeg)), ffmpeg, color=['red', 'blue', 'green', 'grey', 'purple'])
plt.title("ffmpeg")
plt.yticks(range(1, 10, 1))

plt.tick_params(labelsize=8)
plt.savefig("line_cov.png",dpi=1080,format='png', bbox_inches='tight')
plt.show()