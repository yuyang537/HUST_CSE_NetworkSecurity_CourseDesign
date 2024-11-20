
#include "common.h"

// 添加过滤规则函数
struct KernelResponse addFilterRule(char *after,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action) {
	struct APPRequest req;
    struct KernelResponse rsp;
	// 构造规则结构体
	struct IPRule rule;
	if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;  // 源IP地址格式错误
		return rsp;
	}
	if(IPstr2IPint(dip,&rule.daddr,&rule.dmask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;  // 目的IP地址格式错误
		return rsp;
	}
	rule.saddr = rule.saddr;
	rule.daddr = rule.daddr;
	rule.sport = sport;
	rule.dport = dport;
	rule.log = log;
	rule.action = action;
	rule.protocol = proto;
	strncpy(rule.name, name, MAXRuleNameLen);
	// 构造请求消息
	req.tp = REQ_ADDIPRule;
	req.ruleName[0]=0;
	strncpy(req.ruleName, after, MAXRuleNameLen);
	req.msg.ipRule = rule;
	// 与防火墙内核交互
	return exchangeMsgK(&req, sizeof(req));
}

// 修改过滤规则函数
struct KernelResponse changeFilterRule(int key, char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action) {
	struct APPRequest req;
    struct KernelResponse rsp;
	// 构造规则结构体
	struct IPRule rule;
	if(strcmp(sip, "-1") == 0)
		rule.saddr=0, rule.smask=0;  // 源IP地址保持不变
	else if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;  // 源IP地址格式错误
		return rsp;
	}
	if(strcmp(dip, "-1") == 0)
		rule.daddr=0, rule.dmask=0;  // 目的IP地址保持不变
	else if(IPstr2IPint(dip,&rule.daddr,&rule.dmask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;  // 目的IP地址格式错误
		return rsp;
	}
	rule.sport = sport;
	rule.dport = dport;
	rule.log = log;
	rule.action = action;
	rule.protocol = proto;
	strncpy(rule.name, name, MAXRuleNameLen);
	// 构造请求消息
	req.tp = REQ_CHANGEIPRule;
	req.num = key;
	req.msg.ipRule = rule;
	// 与防火墙内核交互
	return exchangeMsgK(&req, sizeof(req));
}

// 删除过滤规则函数
struct KernelResponse delFilterRule(char *name) {
	struct APPRequest req;
	// 构造请求消息
	req.tp = REQ_DELIPRule;
	strncpy(req.ruleName, name, MAXRuleNameLen);
	// 与防火墙内核交互
	return exchangeMsgK(&req, sizeof(req));
}

// 获取所有过滤规则函数
struct KernelResponse getAllFilterRules(void) {
	struct APPRequest req;
	// 构造请求消息并与防火墙内核交互
	req.tp = REQ_GETAllIPRules;
	return exchangeMsgK(&req, sizeof(req));
}

// 添加NAT规则函数
struct KernelResponse addNATRule(char *sip,char *natIP,unsigned short minport,unsigned short maxport) {
	struct APPRequest req;
	struct KernelResponse rsp;
	// 构造NAT规则结构体
	struct NATRecord rule;
	if(IPstr2IPint(natIP,&rule.daddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;  // NAT映射IP地址格式错误
		return rsp;
	}
	if(IPstr2IPint(sip,&rule.saddr,&rule.smask)!=0) {
		rsp.code = ERROR_CODE_WRONG_IP;  // 源IP地址格式错误
		return rsp;
	}
	rule.sport = minport;
	rule.dport = maxport;
	// 构造请求消息
	req.tp = REQ_ADDNATRule;
	req.msg.natRule = rule;
	// 与防火墙内核交互
	return exchangeMsgK(&req, sizeof(req));
}

// 删除NAT规则函数
struct KernelResponse delNATRule(int num) {
	struct APPRequest req;
	struct KernelResponse rsp;
	if(num < 0) {
		rsp.code = ERROR_CODE_NO_SUCH_RULE;  // 规则序号无效
		return rsp;
	}
	req.tp = REQ_DELNATRule;
	req.msg.num = num;
	// 与防火墙内核交互
	return exchangeMsgK(&req, sizeof(req));
}

// 获取所有NAT规则函数
struct KernelResponse getAllNATRules(void) {
	struct APPRequest req;
	// 构造请求消息并与防火墙内核交互
	req.tp = REQ_GETNATRules;
	return exchangeMsgK(&req, sizeof(req));
}

// 设置默认动作函数
struct KernelResponse setDefaultAction(unsigned int action) {
	struct APPRequest req;
	// 构造请求消息
	req.tp = REQ_SETAction;
	req.msg.defaultAction = action;
	// 与防火墙内核交互
	return exchangeMsgK(&req, sizeof(req));
}

// 获取日志记录函数
struct KernelResponse getLogs(unsigned int num) {
	struct APPRequest req;
	// 构造请求消息并与防火墙内核交互
	req.msg.num = num;
	req.tp = REQ_GETAllIPLogs;
	return exchangeMsgK(&req, sizeof(req));
}

// 获取所有连接状态函数
struct KernelResponse getAllConns(void) {
	struct APPRequest req;
	// 构造请求消息并与防火墙内核交互
	req.tp = REQ_GETAllConns;
	return exchangeMsgK(&req, sizeof(req));
}
