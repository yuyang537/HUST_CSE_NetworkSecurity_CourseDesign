#include "common.h"

// 与内核进行消息交换的函数
struct KernelResponse exchangeMsgK(void *smsg, unsigned int slen)
{
	struct sockaddr_nl local;  // 本地netlink地址
	struct sockaddr_nl kpeer;  // 内核netlink地址
	struct KernelResponse rsp; // 响应结构体
	int dlen, kpeerlen = sizeof(struct sockaddr_nl); 
	// 初始化netlink socket
	int skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MYFW);
	if (skfd < 0)
	{
		// printf("[防火墙内核] 无法创建netlink套接字\n");
		rsp.code = ERROR_CODE_EXCHANGE;
		return rsp;
	}
	// 绑定socket和本地地址
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 0;
	if (bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0)
	{
		// printf("[防火墙内核] 绑定套接字失败\n");
		close(skfd);
		rsp.code = ERROR_CODE_EXCHANGE;
		return rsp;
	}
	
	// 设置内核地址
	memset(&kpeer, 0, sizeof(kpeer));
	kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid = 0;
	kpeer.nl_groups = 0;
	// 构造发送消息
	struct nlmsghdr *message = (struct nlmsghdr *)malloc(NLMSG_SPACE(slen) * sizeof(uint8_t));
	if (!message)
	{
		// printf("[防火墙内核] 发送消息内存分配失败\n");
		close(skfd);
		rsp.code = ERROR_CODE_EXCHANGE;
		return rsp;
	}
	memset(message, '\0', sizeof(struct nlmsghdr));
	message->nlmsg_len = NLMSG_SPACE(slen);
	message->nlmsg_flags = 0;
	message->nlmsg_type = 0;
	message->nlmsg_seq = 0;
	message->nlmsg_pid = local.nl_pid;
	memcpy(NLMSG_DATA(message), smsg, slen);
	// 发送消息到内核
	if (!sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *)&kpeer, sizeof(kpeer)))
	{
		// printf("[防火墙内核] 向内核发送消息失败\n");
		close(skfd);
		free(message);
		rsp.code = ERROR_CODE_EXCHANGE;
		return rsp;
	}
	// 接收内核响应
	struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD) * sizeof(uint8_t));
	if (!nlh)
	{
		// printf("[防火墙内核] 接收缓冲区内存分配失败\n");
		close(skfd);
		free(message);
		rsp.code = ERROR_CODE_EXCHANGE;
		return rsp;
	}
	if (!recvfrom(skfd, nlh, NLMSG_SPACE(MAX_PAYLOAD), 0, (struct sockaddr *)&kpeer, (socklen_t *)&kpeerlen))
	{
		// printf("[防火墙内核] 接收内核响应失败\n");
		close(skfd);
		free(message);
		free(nlh);
		rsp.code = ERROR_CODE_EXCHANGE;
		return rsp;
	}
	// 处理接收到的数据
	dlen = nlh->nlmsg_len - NLMSG_SPACE(0);
	rsp.data = malloc(dlen);
	if (!(rsp.data))
	{
		// printf("[防火墙内核] 响应数据内存分配失败\n");
		close(skfd);
		free(message);
		free(nlh);
		rsp.code = ERROR_CODE_EXCHANGE;
		return rsp;
	}
	memset(rsp.data, 0, dlen);
	memcpy(rsp.data, NLMSG_DATA(nlh), dlen);
	rsp.code = dlen - sizeof(struct KernelResponseHeader);
	if (rsp.code < 0)
	{
		rsp.code = ERROR_CODE_EXCHANGE;
	}
	rsp.header = (struct KernelResponseHeader *)rsp.data;
	rsp.body = rsp.data + sizeof(struct KernelResponseHeader);
	// 清理资源并返回
	close(skfd);
	free(message);
	free(nlh);
	return rsp;
}