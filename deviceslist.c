/*************************************************************************
	> File Name: setdevice.c
	> Author: 
	> Mail: 
	> Created Time: Sun 09 Sep 2018 11:09:37 PM PDT
 ************************************************************************/

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include "sniff.h"

/*过滤条件最大长度*/
#define FILTER_LEN (10 * 1024)
/*以太网帧长度*/
#define SIZE_ETHERNET 14
/**/
#define DEVSNAME_LEN 1024

/*分析包相关*/
const stEthernet *pstEthernet;/*ethernet header*/
const stIP *pstIP;/*ip header*/
const stTCP *pstTcp;/*tcp header*/
const stUDP *pstUdp;/*udp header*/
const u_char *pPayload;/*packet payload*/

u_int uiSize_ip;
u_int uiSize_tcp;
u_int uiSize_udp;

void traffic_callback(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet);


int main(int argc, char *argv[])
{
    pcap_if_t *pstAlldevs = NULL;//存放网卡指针入口
    pcap_if_t *pstDevs = NULL;//网卡临时指针变量
    char caErrbuf[PCAP_ERRBUF_SIZE] = {0};//存储错误信息
    int iRet = 0;
    int iLoop = 0;
    int iSelectDevs = -1;
    u_int uiShowUsage = 0;

    char caDevname[DEVSNAME_LEN+1] = {0};
    bpf_u_int32 uiIP = 0;//ip信息
    bpf_u_int32 uiNetmask = 0;//子网掩码信息
    struct in_addr stIn_addr;
    pcap_t *pstHandle = NULL;//网卡句柄

    struct bpf_program stFliter = {0};//存放编译后的bpf
    char g_acFilter[FILTER_LEN + 1] = {0};//条件过滤规则字符串

    /*0 命令行参数处理 */
    if(1 >= argc)
    {
        uiShowUsage = 1;
    }
    else if (2 == argc)
    {
        iSelectDevs = atoi(argv[1]);
    }
    else /* 3 <= argc */
    {
        iSelectDevs = atoi(argv[1]);
        strncpy(g_acFilter, argv[2], FILTER_LEN);
        printf("Set filter: %s", g_acFilter);
    }

    /*1 查找所有网卡*/
    iRet = pcap_findalldevs(&pstAlldevs, caErrbuf);//查找所有网卡
    if(0 != iRet)//查找网卡错误处理
    {
        fprintf(stderr,"Couldn't find default device: (%s)\r\n",caErrbuf);
        return (-1);
    }
    printf("Device:%d\r\n",iRet);
    
    /*2 打印所有网卡信息*/
    pstDevs = pstAlldevs;
    iLoop = 0;
    printf("Device List:\r\n");
    while(NULL != pstDevs)//遍历网卡列表并打印
    {
        if(iSelectDevs == iLoop){
            strncpy(caDevname, pstDevs->name, DEVSNAME_LEN);
            printf("-> (%d)  %s (%s)\r\n",iLoop, pstDevs->name,pstDevs->description);//打印网卡信息
            pstDevs = pstDevs->next;//指向下一个元素地址
        }
        else{
            printf("   (%d)  %s (%s)\r\n",iLoop, pstDevs->name,pstDevs->description);//打印网卡信息
            pstDevs = pstDevs->next;//指向下一个元素地址
        }
        ++iLoop;
    }
    pcap_freealldevs(pstAlldevs);//释放
    pstAlldevs = NULL;
    
    if(1 == uiShowUsage)
    {
        printf("Please key: <select> [filter] \r\n");
        return (0);
    }


    if(0 == strlen(caDevname)){
        printf("Couldn't find the select device!\r\n ");
        return (-1);
    }




    /*3 获取本地设备ip，mask*/
    iRet = pcap_lookupnet(caDevname,&uiIP,&uiNetmask,caErrbuf);
    if(0 != iRet)
    {
        fprintf(stderr,"Couldn't look up net(%s)\r\n",caErrbuf);
        uiIP = 0;
        uiNetmask = 0xFFFFFFFF;
    }

    /*打印ip，mask*/
    #if 0
    stIn_addr.s_addr = uiIP;
    char *pcIP = inet_ntoa(stIn_addr);
    if(NULL == pcIP)
    {
        printf("ip error\r\n");
        return (-1);
    }
    printf("uiNetmask:%d\r\n", uiNetmask);
    stIn_addr.s_addr = uiNetmask;
    char *pcNetmask = inet_ntoa(stIn_addr);
    if(NULL == pcNetmask)
    {
        printf("mask error\r\n");
    }
    printf("netmask:%s\r\n", pcNetmask);
    #endif

    /*4 打开网络接口*/
    /*参数一：网卡名称     参数二：数据最大长度  参数三:是否混杂模式
     *参数四：超时时间(ms) 参数五：错误信息*/
    pstHandle = pcap_open_live(caDevname,65535,1,500,caErrbuf);
    if(NULL == pstHandle)
    {
        fprintf(stderr,"Couldn't not open device %s(%s)\r\n",caDevname,caErrbuf);
        return (-1);
    }
    
    /*5 过滤条件*/
    /*参数1：网卡句柄 参数2：过滤器地址 参数3：过滤条件字符串 
     *参数4：是否优化 参数5：子网掩码*/
    iRet = pcap_compile(pstHandle, &stFliter, g_acFilter,0,uiNetmask);
    if(0 != iRet)
    {
        fprintf(stderr, "Couldn't parse the filter\"%s\"!(%s)",g_acFilter,pcap_geterr(pstHandle));
        return (-1);
    }
    iRet = pcap_setfilter(pstHandle,&stFliter);
    if(0 != iRet)
    {
        fprintf(stderr, "Couldn't set filter\"%s\"!(%s)",g_acFilter,pcap_geterr(pstHandle));
        return (-1);
    }

    /*6 获取数据包*/
    /*参数1：网卡句柄   参数2：报文个数 
     *参数3：回调函数   参数4：向回调函数传递的参数*/
    iRet = pcap_loop(pstHandle,10,traffic_callback,NULL);
    if(0 != iRet)
    {
        fprintf(stderr,"Couldn't loop");
        return -1;
    }
    /*7 处理包数据(callback)*/

    /*8 关闭网卡,释放网络接口*/
    pcap_close(pstHandle);
    pstHandle = NULL;

    return (0);
}



void traffic_callback(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    printf("Receives a packet (%ubytes/%ubytes)\r\n",pkthdr->caplen,pkthdr->len);
    
    /*Ethernet Header*/
    pstEthernet = (stEthernet *) (packet);
    printf("sMAC:");
    int i = 0;
    while(i < 5){
        printf("%x ",pstEthernet->ether_shost[i]);
        ++i;
    }
    printf(" ==> ");
    printf("dMAC:");
    i = 0;
    while(i < 5){
        printf("%x ",pstEthernet->ether_dhost[i]);
        ++i;
    }
    printf("\r\n");
    printf("ether_type:%#X\r\n",ntohs(pstEthernet->ether_type));
    /*IP Header*/
    pstIP = (stIP *) (packet + SIZE_ETHERNET);
    uiSize_ip = IP_HL(pstIP)*4;
    if(uiSize_ip < 20){
        printf("Invalid IP header length: %u bytes\r\n\r\n",uiSize_ip);
        return;
    }
    printf("IP_proto:%#X\r\n", pstIP->ip_p );/*0X06->tcp  0X11->udp*/
    printf("sip:%s ==> dip:%s\r\n",inet_ntoa(pstIP->ip_src),inet_ntoa(pstIP->ip_dst));
    if(6 == pstIP->ip_p){
        /*TCP Header*/
        pstTcp = (stTCP *) (packet + SIZE_ETHERNET + uiSize_ip);
        uiSize_tcp = TH_OFF(pstTcp)*4;
        if(uiSize_tcp < 20){
            printf("Invalid TCP header lenght: %u bytes\r\n\r\n",uiSize_tcp);
            return;
        }
        printf("sport:%u ==> dport:%u\r\n\r\n", ntohs(pstTcp->th_sport), ntohs(pstTcp->th_dport));
        //pPayload = (u_char *) (packet + SIZE_ETHERNET + uiSize_tcp);
        }
    else if( 17 == pstIP->ip_p ){
        pstUdp = (stUDP *) (packet + SIZE_ETHERNET + uiSize_ip);
        uiSize_udp = ntohs(pstUdp->uh_length);
        if(uiSize_udp < 8){
            printf("Invalid UDP header lenght: %u bytes\r\n\r\n",uiSize_tcp);
            return;
        }
        printf("sport:%u ==> dport:%u\r\n\r\n", ntohs(pstUdp->uh_sport), ntohs(pstUdp->uh_dport));
       //printf("udp:%u\r\n", ntohs(pstUdp->uh_length) );
    }
    
    

    return;
}
