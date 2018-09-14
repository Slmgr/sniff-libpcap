# sniff-libpcap
> 基于libcap函数库的TCP/IP/UDP抓包解包工具
# 运行环境
> 有libpcap函数库的linux或FreeBSD
# 安装环境
## Linux
### Cent OS
>> libpcap依赖于一些其他库，因而先安装其它库
``` bash
# yum install bison
# yum install flex
# yum install m4
```
在libcap官方网站下载库并安装:www.tcpdump.org
``` bash
# cd /下载的路径
# tar zxvf 下载的文件名 解压完的路径
# cd 解压完的路径/
# ./configure 
# make
# make install
# yum install libpcap-devel
```
### Ubuntu
>> libpcap依赖于一些其他库，因而先安装其它库
``` bash
# apt-get install bison
# apt-get install flex
# apt-get install m4
```
>> 在libcap官方网站下载库并安装:www.tcpdump.org
``` bash
# cd /下载的路径
# tar zxvf 下载的文件名 解压完的路径
# cd 解压完的路径/
# ./configure 
# make
# make install
# yum install libpcap-devel
```
## Mac OS
``` bash
# brew install bison
# brew install flex
# brew install m4
```
>> 在libcap官方网站下载库并安装:www.tcpdump.org
``` bash
# cd /下载的路径
# tar zxvf 下载的文件名 解压完的路径
# cd 解压完的路径/
# ./configure 
# make
# make install
# yum install libpcap-devel
```
>> 测试libpcap库是否安装成功
``` C
//device.c
#include <stdio.h>
#include <pcap/pcap.h>
int main(int argc,char *argv[]) {
  char *dev,errbuf[PCAP_ERRBUF_SIZE];
  dev=pcap_lookupdev(errbuf);
  if(dev==NULL) {
    printf("couldn't find default device: %s\n",errbuf);
    return(2);
  }
  printf("Device: %s\n",dev);
  return(0);
} 
```
GCC编译
``` bash
# gcc device.c -o device -lpcap
```
# 测试运行
> gcc编译时一定要加-lpcap
> 运行时注意传参
``` bash
# ./devicelist <所选网卡> [过滤规则]
```
# 致谢
- 胡桃夹子 http://hutaow.com
- J·初心者 http://mengz.iteye.com
