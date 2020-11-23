aflFiles = open("/home/dp/coverage/hybrid-afl-files", "r")
chunkAflFiles = open("/home/dp/coverage/hybrid-chunk-afl-files", "r")
aflFile = aflFiles.readline().strip()
chunkAflFile = chunkAflFiles.readline().strip()
while aflFile and chunkAflFile:
    aflLine = aflFiles.readline()
    chunkAflLine = chunkAflFiles.readline()
    gap = len(aflLine.split(",")) - len(chunkAflLine.split(","))
    if(gap > 0):
        print("afl more " + str(gap) + " " + aflFile)
    if(gap < 0):
        print("chunk-afl more " + str(-gap) + " " + chunkAflFile)
    aflFile = aflFiles.readline().strip()
    chunkAflFile = chunkAflFiles.readline().strip()

list1 = [1558, 1563, 1564, 1565, 1566, 1567, 1568, 1569, 1570, 1571, 1572, 1573, 1574, 1575, 1576, 1577, 1578, 1579, 1580, 1581, 1582, 1583, 1584, 1606, 1608, 1609, 1610, 1611, 510, 568, 569, 570, 573, 574, 575, 576, 577, 580, 585, 586, 587, 588, 589, 590, 592, 604, 605, 606, 608, 609, 610, 611, 612, 613, 615, 618, 619, 620, 621, 622, 623, 624, 625, 628, 629, 630, 635, 636, 637, 638, 639, 640, 641, 642, 643, 644, 645, 646, 660, 661, 662, 663, 664, 665, 667, 668, 669, 670, 671, 672, 674, 676, 732, 734, 735, 736, 738, 746, 747, 752, 753, 754, 755, 756, 757, 758, 759, 760, 762, 763, 764, 765, 766, 767, 768, 770, 771,
         772, 773, 774, 775, 776, 778, 779, 780, 781, 782, 783, 784, 789, 790, 791, 795, 796, 799, 801, 809, 810, 814, 815, 819, 820, 824, 825, 829, 830, 833, 834, 835, 838, 843, 844, 845, 847, 849, 850, 851, 852, 853, 854, 855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 865, 866, 867, 868, 871, 872, 878, 880, 882, 884, 886, 887, 888, 889, 890, 892, 897, 898, 899, 900, 901, 903, 904, 905, 906, 909, 910, 911, 912, 923, 926, 928, 929, 930, 932, 935, 936, 937, 942, 943, 945, 946, 949, 950, 952, 953, 954, 955, 956, 958, 963, 965, 966, 967, 968, 969, 971, 972, 973, 974, 975, 976, 978, 979, 980, 982, 983, 986, 987, 989, 990]
list1.sort()
list2 = [1558,1563,1564,1565,1566,1567,1568,1569,1570,1571,1572,1573,1574,1575,1576,1577,1578,1579,1580,1581,1582,1583,1584,1606,1608,1609,1610,1611,510,568,569,570,573,574,575,576,577,580,585,586,587,588,589,590,592,604,605,606,608,609,610,611,612,613,615,618,619,620,621,622,623,624,625,628,629,630,660,661,662,663,664,665,667,668,669,670,671,672,674,676,732,734,735,736,738,746,747,752,753,754,755,756,757,758,759,760,762,763,764,765,766,767,768,770,771,772,773,774,775,776,778,779,780,781,782,783,784,789,790,791,795,796,799,801,809,810,814,815,833,834,835,838,843,844,845,847,849,850,851,852,853,854,855,856,857,858,859,860,862,864,866,868,871,872,884,886,887,888,889,892,897,898,899,900,901,903,904,905,906,909,910,911,912,923,926,928,929,930,932,935,936,937,942,943,945,946,963,965,966,967,969,971,972,973,974]
list2.sort()
set = set(list1).difference(set(list2))
print(set)
