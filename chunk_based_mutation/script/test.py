import time
import os
import datetime

time2 = os.path.getctime(
    "/home/dp/imagemagickoutput-hybrid/chunk-afl-slave/queue/id:002310,src:002033,op:havoc,rep:2")
time1 = os.path.getctime(
    "/home/dp/imagemagickoutput-hybrid/chunk-afl-slave/queue/id:005555,src:000185+005212,op:splice,rep:16")
m, s = divmod(time2 - time1, 60)
h, m = divmod(m, 60)

print(time.ctime(time1))
print(time.ctime(time2))

print(m)
print(h)
#print(time.strftime("%Y-%m-%d %H:%M:%S", time2))
