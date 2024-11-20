#include "contact.h"

int showRules(struct IPRule *rules, int len);
int showNATRules(struct NATRecord *rules, int len); 
int showLogs(struct IPLog *logs, int len);
int showConns(struct ConnLog *logs, int len);

// 处理来自内核的响应消息
void dealResponseAtCmd(struct KernelResponse rsp) {
	// 判断错误码并给出相应提示
	switch (rsp.code) {
	case ERROR_CODE_EXIT:
		exit(0);
		break;
	case ERROR_CODE_NO_SUCH_RULE:
		printf("[防火墙内核] 错误: 未找到指定的规则\n");
		return;
	case ERROR_CODE_WRONG_IP:
		printf("[防火墙内核] 错误: IP地址格式不正确\n");
		return;
	}
	if(rsp.code < 0 || rsp.data == NULL || rsp.header == NULL || rsp.body == NULL) 
		return;
	// 根据响应类型处理数据
	switch (rsp.header->bodyTp) {
	case RSP_Only_Head:
		printf("[防火墙内核] 成功删除 %d 条规则\n", rsp.header->arrayLen);
		break;
	case RSP_MSG:
		printf("[防火墙内核] 消息: %s\n", (char*)rsp.body);
		break;
	case RSP_IPRules:
		showRules((struct IPRule*)rsp.body, rsp.header->arrayLen);
		break;
	case RSP_NATRules:
		showNATRules((struct NATRecord*)rsp.body, rsp.header->arrayLen);
		break;
	case RSP_IPLogs:
		showLogs((struct IPLog*)rsp.body, rsp.header->arrayLen);
		break;
	case RSP_ConnLogs:
		showConns((struct ConnLog*)rsp.body, rsp.header->arrayLen);
		break;
	}
	if(rsp.header->bodyTp != RSP_Only_Head && rsp.body != NULL) {
		free(rsp.data);
	}
}

// 打印分隔线
void printLine(int len) {
	int i;
	for(i = 0; i < len; i++) {
		printf("-");
	}
	printf("\n");
}

// 显示单条防火墙规则
int showOneRule(struct IPRule rule) {
	char saddr[25],daddr[25],sport[13],dport[13],proto[6],action[8],log[5];
	// 转换IP地址格式
	IPint2IPstr(rule.saddr,rule.smask,saddr);
	IPint2IPstr(rule.daddr,rule.dmask,daddr);
	// 转换端口格式
	if(rule.sport == 0xFFFFu)
		strcpy(sport, "任意");
	else if((rule.sport >> 16) == (rule.sport & 0xFFFFu))
		sprintf(sport, "仅 %u", (rule.sport >> 16));
	else
		sprintf(sport, "%u~%u", (rule.sport >> 16), (rule.sport & 0xFFFFu));
	if(rule.dport == 0xFFFFu)
		strcpy(dport, "任意");
	else if((rule.dport >> 16) == (rule.dport & 0xFFFFu))
		sprintf(dport, "仅 %u", (rule.dport >> 16));
	else
		sprintf(dport, "%u~%u", (rule.dport >> 16), (rule.dport & 0xFFFFu));
	// 转换动作类型
	if(rule.action == NF_ACCEPT) {
		sprintf(action, "允许");
	} else if(rule.action == NF_DROP) {
		sprintf(action, "拒绝");
	} else {
		sprintf(action, "其他");
	}
	// 转换协议类型
	if(rule.protocol == IPPROTO_TCP) {
		sprintf(proto, "TCP");
	} else if(rule.protocol == IPPROTO_UDP) {
		sprintf(proto, "UDP");
	} else if(rule.protocol == IPPROTO_ICMP) {
		sprintf(proto, "ICMP");
	} else if(rule.protocol == IPPROTO_IP) {
		sprintf(proto, "IP");
	} else {
		sprintf(proto, "其他");
	}
	// 转换日志标记
	if(rule.log) {
		sprintf(log, "是");
	} else {
		sprintf(log, "否");
	}
	// 打印规则信息
	printf("| %-*s | %-18s | %-18s | %-11s | %-11s | %-8s | %-6s | %-3s |\n", MAXRuleNameLen,
	rule.name, saddr, daddr, sport, dport, proto, action, log);
	printLine(111);
}

// 显示所有防火墙规则
int showRules(struct IPRule *rules, int len) {
	int i;
	if(len == 0) {
		printf("[防火墙内核] 当前没有任何规则\n");
		return 0;
	}
	printLine(111);
	printf("| %-*s | %-18s | %-18s | %-11s | %-11s | %-8s | %-6s | %-3s |\n", MAXRuleNameLen,
	 "规则名称", "源IP地址", "目标IP地址", "源端口", "目标端口", "协议", "动作", "记录");
	printLine(111);
	for(i = 0; i < len; i++) {
		showOneRule(rules[i]);
	}
	return 0;
}

// 显示所有NAT规则
int showNATRules(struct NATRecord *rules, int len) {
	int i, col = 66;
	char saddr[25],daddr[25];
	if(len == 0) {
		printf("[防火墙内核] 当前没有任何NAT规则\n");
		return 0;
	}
	printLine(col);
	printf("| 序号 | %18s |->| %-18s | %-11s |\n", "源IP地址", "NAT地址", "NAT端口");
	printLine(col);
	for(i = 0; i < len; i++) {
		IPint2IPstr(rules[i].saddr,rules[i].smask,saddr);
		IPint2IPstrNoMask(rules[i].daddr,daddr);
		printf("| %3d | %18s |->| %-18s | %5u~%-5u |\n", i, saddr, daddr, rules[i].sport, rules[i].dport);
		printLine(col);
	}
	return 0;
}

// 显示单条日志记录
int showOneLog(struct IPLog log) {
	struct tm * timeinfo;
	char saddr[25],daddr[25],proto[6],action[8],tm[21];
	// 转换IP地址格式
	IPint2IPstrWithPort(log.saddr, log.sport, saddr);
	IPint2IPstrWithPort(log.daddr, log.dport, daddr);
	// 转换动作类型
	if(log.action == NF_ACCEPT) {
		sprintf(action, "[允许]");
	} else if(log.action == NF_DROP) {
		sprintf(action, "[拒绝]");
	} else {
		sprintf(action, "[未知]");
	}
	// 转换协议类型
	if(log.protocol == IPPROTO_TCP) {
		sprintf(proto, "TCP");
	} else if(log.protocol == IPPROTO_UDP) {
		sprintf(proto, "UDP");
	} else if(log.protocol == IPPROTO_ICMP) {
		sprintf(proto, "ICMP");
	} else if(log.protocol == IPPROTO_IP) {
		sprintf(proto, "IP");
	} else {
		sprintf(proto, "其他");
	}
	// 转换时间格式
	timeinfo = localtime(&log.tm);
	sprintf(tm, "%4d-%02d-%02d %02d:%02d:%02d",
		1900 + timeinfo->tm_year, 1 + timeinfo->tm_mon, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
	// 打印日志信息
	printf("[%s] %-9s %s->%s 协议=%s 长度=%uB\n",
		tm, action, saddr, daddr, proto, log.len);
}

// 显示所有日志记录
int showLogs(struct IPLog *logs, int len) {
	int i;
	if(len == 0) {
		printf("[防火墙内核] 当前没有任何日志记录\n");
		return 0;
	}
	printf("总计: %d条记录\n", len);
	for(i = 0; i < len; i++) {
		showOneLog(logs[i]);
	}
	return 0;
}

// 显示单个连接信息
int showOneConn(struct ConnLog log) {
	struct tm * timeinfo;
	char saddr[25],daddr[25],proto[6];
	// 转换IP地址格式
	IPint2IPstrWithPort(log.saddr,log.sport,saddr);
	IPint2IPstrWithPort(log.daddr,log.dport,daddr);
	// 转换协议类型
	if(log.protocol == IPPROTO_TCP) {
		sprintf(proto, "TCP");
	} else if(log.protocol == IPPROTO_UDP) {
		sprintf(proto, "UDP");
	} else if(log.protocol == IPPROTO_ICMP) {
		sprintf(proto, "ICMP");
	} else if(log.protocol == IPPROTO_IP) {
		sprintf(proto, "任意");
	} else {
		sprintf(proto, "其他");
	}
	printf("| %-5s |  %21s |->|  %21s | 已建立 |\n",proto, saddr, daddr);
	if(log.natType == NAT_TYPE_SRC) {
		IPint2IPstrWithPort(log.nat.daddr, log.nat.dport, saddr);
		printf("| %-5s |=>%21s |->|  %21c | %11c |\n", "NAT", saddr, ' ', ' ');
	} else if(log.natType == NAT_TYPE_DEST) {
		IPint2IPstrWithPort(log.nat.daddr, log.nat.dport, daddr);
		printf("| %-5s |  %21c |->|=>%21s | %11c |\n", "NAT", ' ', daddr, ' ');
	}
}

// 显示所有连接信息
int showConns(struct ConnLog *logs, int len) {
	int i, col = 78;
	if(len == 0) {
		printf("[防火墙内核] 当前没有任何活动连接\n");
		return 0;
	}
	printf("当前连接数: %d\n", len);
	printLine(col);
	printf("| %-5s |  %21s |->|  %21s | %11s |\n", "协议", "源地址", "目标地址", "状态");
	printLine(col);
	for(i = 0; i < len; i++) {
		showOneConn(logs[i]);
	}
	printLine(col);
	return 0;
}
