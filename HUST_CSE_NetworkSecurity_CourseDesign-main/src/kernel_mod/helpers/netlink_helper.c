#include "helper.h"

static struct sock *nlsk = NULL;

int nlSend(unsigned int pid, void *data, unsigned int len) {
	int retval;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	// 初始化 sk_buff
	skb = nlmsg_new(len, GFP_ATOMIC);
	if (skb == NULL) {
		printk(KERN_WARNING "[防火墙内核] 分配回复 nlmsg skb 失败！\n");
		return -1;
	}
	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(len) - NLMSG_HDRLEN, 0);
	// 发送数据
	memcpy(NLMSG_DATA(nlh), data, len);
    //NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;
	retval = netlink_unicast(nlsk, skb, pid, MSG_DONTWAIT);
	printk("[防火墙内核] 发送到用户 pid=%d, 长度=%d, 返回值=%d\n", pid, nlh->nlmsg_len - NLMSG_SPACE(0), retval);
	return retval;
}

void nlRecv(struct sk_buff *skb) {
	void *data;
	struct nlmsghdr *nlh = NULL;
	unsigned int pid, len;
    // 检查 skb
    nlh = nlmsg_hdr(skb);
	if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) {
		printk(KERN_WARNING "[防火墙内核] 非法的 netlink 数据包！\n");
		return;
	}
    // 处理数据
	data = NLMSG_DATA(nlh);
    pid = nlh->nlmsg_pid;
    len = nlh->nlmsg_len - NLMSG_SPACE(0);
	if(len < sizeof(struct APPRequest)) {
		printk(KERN_WARNING "[防火墙内核] 数据包大小小于 APPRequest！\n");
		return;
	}
	printk("[防火墙内核] 从用户接收到数据: 用户 pid=%d, 长度=%d\n", pid, len);
	dealAppMessage(pid, data, len);
}

struct netlink_kernel_cfg nltest_cfg = {
	.groups = 0,
	.flags = 0,
	.input = nlRecv,
	.cb_mutex = NULL,
	.bind = NULL,
	.unbind = NULL,
	.compare = NULL,
};

struct sock *netlink_init() {
    nlsk = netlink_kernel_create(&init_net, NETLINK_MYFW, &nltest_cfg);
	if (!nlsk) {
		printk(KERN_WARNING "[防火墙内核] 无法创建 netlink 套接字\n");
		return NULL;
	}
	printk("[防火墙内核] netlink_kernel_create() 成功, nlsk = %p\n", nlsk);
    return nlsk;
}

void netlink_release() {
    netlink_kernel_release(nlsk);
}