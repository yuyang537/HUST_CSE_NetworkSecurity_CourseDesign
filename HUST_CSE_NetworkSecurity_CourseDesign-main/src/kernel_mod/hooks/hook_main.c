#include "tools.h"
#include "helper.h"
#include "hook.h"

unsigned int DEFAULT_ACTION = NF_ACCEPT;

unsigned int hook_main(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
    struct IPRule rule;
    struct connNode *conn;
    unsigned short sport, dport;  // 源端口和目的端口
    unsigned int sip, dip, action = DEFAULT_ACTION;  // 源IP、目的IP和处理动作
    int isMatch = 0, isLog = 1;  // 是否匹配规则标志和是否记录日志标志(默认记录)
    
    // 初始化网络包头部信息
    struct iphdr *header = ip_hdr(skb);
    getPort(skb,header,&sport,&dport);  // 获取端口信息
    sip = ntohl(header->saddr);  // 获取源IP地址
    dip = ntohl(header->daddr);  // 获取目的IP地址
    
    // 查询连接跟踪表,检查是否存在已建立的连接
    conn = hasConn(sip, dip, sport, dport);
    if(conn != NULL) {  // 如果是已有连接
        if(conn->needLog)  // 需要记录日志时
            addLogBySKB(action, skb);  // 添加连接日志
        return NF_ACCEPT;  // 允许通过
    }
    
    // 遍历过滤规则表进行规则匹配
    rule = matchIPRules(skb, &isMatch);
    if(isMatch) {  // 如果匹配到规则
        printk(KERN_DEBUG "[防火墙内核] 匹配到规则: %s\n", rule.name);
        action = (rule.action==NF_ACCEPT) ? NF_ACCEPT : NF_DROP;  // 设置处理动作
        if(rule.log) {  // 规则要求记录日志
            isLog = 1;
            addLogBySKB(action, skb);  // 添加规则匹配日志
        }
    }
    
    // 对于允许通过的包,更新连接跟踪表
    if(action == NF_ACCEPT) {
        addConn(sip,dip,sport,dport,header->protocol,isLog);
    }
    return action;  // 返回处理动作
}