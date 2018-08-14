# UPER
ASN.1 to C language

ASN.1是定义抽象数据类型规格形式的标准。是用于描述数据的表示、编码、传输、解码的灵活的记法。它提供了一套正式、无歧义和精确的规则，以描述独立于特定计算机硬件的对象结构。
ASN.1是通信协议中描述数据传输的正式标记（notation），它与语言实现和物理表示无关，与应用的复杂度无关。ASN.1特别适合表示现代通信应用中那些复杂的、变化的及可扩展的数据结构。
ASN.1发送任何形式（音频、视频、数据等等）的信息都必须用数字传送。ASN.1只能包含信息的结构方面（没有已经定义的或考虑到的处理数据值的操作）。它不是一个编程语言。 ASN.1格式数据有多种编码方式，包括BER、DER、XER、PER/UPER等。网上的例程只涉及到BER编码，没有关于UPER编码的历程。
本工程将ASN文件编译为.c和.h文件，通过调用API实现UPER编码和解码。



1、编译：信号灯数据格式要先填充为.asn格式文件，可以根据数据增删来修改.asn文件，使用asn1c工具编译为.c和.h文件，这里存为try.asn文件

   asn1c  -gen-PER  *.asn

2、编解码业务写在main.c文件中

3、在生成的.c和.h文件夹中编译运行
gcc *.c -I. -o exe
