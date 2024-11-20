#include "dependency.h"
#include "hook.h"
#include "helper.h"

// 定义入站过滤钩子
static struct nf_hook_ops nfop_in={
	.hook = hook_main,          // 钩子处理函数
	.pf = PF_INET,             // IPv4协议族
	.hooknum = NF_INET_PRE_ROUTING,  // 数据包进入路由前
	.priority = NF_IP_PRI_FIRST      // 最高优先级
};

// 定义出站过滤钩子
static struct nf_hook_ops nfop_out={
	.hook = hook_main,          // 钩子处理函数
	.pf = PF_INET,             // IPv4协议族
	.hooknum = NF_INET_POST_ROUTING, // 数据包路由后
	.priority = NF_IP_PRI_FIRST      // 最高优先级
};

// 定义NAT入站钩子
static struct nf_hook_ops natop_in={
	.hook = hook_nat_in,        // NAT入站处理函数
	.pf = PF_INET,             // IPv4协议族
	.hooknum = NF_INET_PRE_ROUTING,  // 数据包进入路由前
	.priority = NF_IP_PRI_NAT_DST    // 目的NAT优先级
};

// 定义NAT出站钩子
static struct nf_hook_ops natop_out={
	.hook = hook_nat_out,       // NAT出站处理函数
	.pf = PF_INET,             // IPv4协议族
	.hooknum = NF_INET_POST_ROUTING, // 数据包路由后
	.priority = NF_IP_PRI_NAT_SRC    // 源NAT优先级
};

// 模块初始化函数
static int mod_init(void){
	printk("[防火墙内核] 防火墙模块已成功加载\n");
	nf_register_net_hook(&init_net,&nfop_in);    // 注册入站过滤钩子
	nf_register_net_hook(&init_net,&nfop_out);   // 注册出站过滤钩子
	nf_register_net_hook(&init_net,&natop_in);   // 注册NAT入站钩子
	nf_register_net_hook(&init_net,&natop_out);  // 注册NAT出站钩子
	netlink_init();  // 初始化netlink通信
	conn_init();     // 初始化连接跟踪
	return 0;
}

// 模块卸载函数
static void mod_exit(void){
	printk("[防火墙内核] 防火墙模块正在卸载\n");
	nf_unregister_net_hook(&init_net,&nfop_in);    // 注销入站过滤钩子
	nf_unregister_net_hook(&init_net,&nfop_out);   // 注销出站过滤钩子
	nf_unregister_net_hook(&init_net,&natop_in);   // 注销NAT入站钩子
	nf_unregister_net_hook(&init_net,&natop_out);  // 注销NAT出站钩子
	netlink_release();  // 释放netlink资源
	conn_exit();        // 清理连接跟踪
}

MODULE_LICENSE("GPL");           // 模块采用GPL协议
MODULE_AUTHOR("ssd");           // 模块作者
module_init(mod_init);          // 注册模块初始化函数
module_exit(mod_exit);          // 注册模块卸载函数
