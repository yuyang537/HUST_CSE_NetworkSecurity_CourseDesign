#include "tools.h"

/**
 * 从网络数据包中获取源端口和目标端口
 * @param skb 网络数据包缓冲区
 * @param hdr IP头部结构
 * @param src_port 源端口指针
 * @param dst_port 目标端口指针
 */
void getPort(struct sk_buff *skb, struct iphdr *hdr, unsigned short *src_port, unsigned short *dst_port){
	struct tcphdr *tcpHeader;
	struct udphdr *udpHeader;
	switch(hdr->protocol){
		case IPPROTO_TCP:
			//printk("[防火墙内核] 检测到TCP协议数据包\n");
			tcpHeader = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
			*src_port = ntohs(tcpHeader->source);
			*dst_port = ntohs(tcpHeader->dest);
			break;
		case IPPROTO_UDP:
			//printk("[防火墙内核] 检测到UDP协议数据包\n"); 
			udpHeader = (struct udphdr *)(skb->data + (hdr->ihl * 4));
			*src_port = ntohs(udpHeader->source);
			*dst_port = ntohs(udpHeader->dest);
			break;
		case IPPROTO_ICMP:
		default:
			//printk("[防火墙内核] 检测到其他类型协议数据包\n");
			*src_port = 0;
			*dst_port = 0;
			break;
	}
}

/**
 * 判断IP地址是否匹配
 * @param ipl 待检测的IP地址
 * @param ipr 规则中的IP地址
 * @param mask IP掩码
 * @return 如果IP地址匹配返回true，否则返回false
 */
bool isIPMatch(unsigned int ipl, unsigned int ipr, unsigned int mask) {
	return (ipl & mask) == (ipr & mask);
}