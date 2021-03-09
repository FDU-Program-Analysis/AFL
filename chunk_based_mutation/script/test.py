import matplotlib.pyplot as plt
import numpy as np
import os

x = np.linspace(-1,1,50)#从(-1,1)均匀取50个点
y = 2 * x
os.system('export DISPLAY=:0.0')
plt.plot(x,y)
plt.show()