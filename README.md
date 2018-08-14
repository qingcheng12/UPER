# UPER
ASN.1 to C language

1、编译：信号灯数据格式要先填充为.asn格式文件，可以根据数据增删来修改.asn文件，使用asn1c工具编译为.c和.h文件，这里存为try.asn文件

   asn1c  -gen-PER  *.asn

2、编解码业务写在main.c文件中

3、在生成的.c和.h文件夹中编译运行
gcc *.c -I. -o exe
