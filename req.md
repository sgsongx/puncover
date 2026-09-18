# 需求

1.现在通过puncover axf得到的总CODE static大小无法和FLASH RAM实际占用对应起来. 请通过添加map文件, 补充, 完成优化code static占用分析, 从而与map中的实际占用对应起来. 也请把stack和heap加入分析
2.在生成的分析页面中, 给非局部变量增加两个信息, 有初始值的补充FLASH加载地址, 以及在运行中的RAM地址. 而不是只有大小占用信息