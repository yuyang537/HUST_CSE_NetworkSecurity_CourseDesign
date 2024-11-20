#ifndef _NETLINK_HELPER_H
#define _NETLINK_HELPER_H

#include "dependency.h"

// ---- 应用程序与内核通信协议定义 ------
#define MAXRuleNameLen 11 // 规则名称最大长度

// 请求类型定义
#define REQ_GETAllIPRules 1  // 获取所有IP规则
#define REQ_ADDIPRule 2      // 添加IP规则
#define REQ_CHANGEIPRule 16  // 修改IP规则
#define REQ_DELIPRule 3      // 删除IP规则
#define REQ_SETAction 4      // 设置默认动作
#define REQ_GETAllIPLogs 5   // 获取所有IP日志
#define REQ_GETAllConns 6    // 获取所有连接
#define REQ_ADDNATRule 7     // 添加NAT规则
#define REQ_DELNATRule 8     // 删除NAT规则
#define REQ_GETNATRules 9    // 获取NAT规则

// 响应类型定义
#define RSP_Only_Head 10     // 仅包含头部信息
#define RSP_MSG 11           // 包含消息内容
#define RSP_IPRules 12       // 包含IP规则数组
#define RSP_IPLogs 13        // 包含IP日志数组
#define RSP_NATRules 14      // 包含NAT规则数组
#define RSP_ConnLogs 15      // 包含连接日志数组

// IP规则结构体定义
struct IPRule {
    char name[MAXRuleNameLen+1];  // 规则名称
    unsigned int saddr;           // 源IP地址
    unsigned int smask;           // 源IP掩码
    unsigned int daddr;           // 目标IP地址
    unsigned int dmask;           // 目标IP掩码
    unsigned int sport;           // 源端口范围(高16位为最小值,低16位为最大值)
    unsigned int dport;           // 目标端口范围(高16位为最小值,低16位为最大值)
    u_int8_t protocol;           // 协议类型
    unsigned int action;          // 执行动作
    unsigned int log;            // 是否记录日志
    struct IPRule* nx;           // 下一条规则指针
};

// IP日志结构体定义
struct IPLog {
    long tm;                     // 时间戳
    unsigned int saddr;          // 源IP地址
    unsigned int daddr;          // 目标IP地址
    unsigned short sport;        // 源端口
    unsigned short dport;        // 目标端口
    u_int8_t protocol;          // 协议类型
    unsigned int len;           // 数据包长度
    unsigned int action;        // 执行动作
    struct IPLog* nx;           // 下一条日志指针
};

// NAT记录/规则结构体定义
struct NATRecord {
    unsigned int saddr;          // 原始源IP地址
    unsigned int smask;          // 源IP掩码(仅规则使用)
    unsigned int daddr;          // NAT转换后IP地址

    unsigned short sport;        // 原始源端口/最小端口范围
    unsigned short dport;        // NAT转换后端口/最大端口范围
    unsigned short nowPort;      // 当前使用端口(仅记录使用)
    struct NATRecord* nx;        // 下一条记录指针
};

// 连接日志结构体定义
struct ConnLog {
    unsigned int saddr;          // 源IP地址
    unsigned int daddr;          // 目标IP地址
    unsigned short sport;        // 源端口
    unsigned short dport;        // 目标端口
    u_int8_t protocol;          // 协议类型
    int natType;                // NAT类型
    struct NATRecord nat;       // NAT记录
};

// 应用请求结构体定义
struct APPRequest {
    unsigned int tp;            // 请求类型
    char ruleName[MAXRuleNameLen+1];  // 规则名称
    int num;                    // 数量
    union {
        struct IPRule ipRule;    // IP规则
        struct NATRecord natRule; // NAT规则
        unsigned int defaultAction; // 默认动作
        unsigned int num;        // 数量
    } msg;                      // 消息内容
};

// 内核响应头部结构体定义
struct KernelResponseHeader {
    unsigned int bodyTp;        // 响应类型
    unsigned int arrayLen;      // 数组长度
};

// NAT类型定义
#define NAT_TYPE_NO 0          // 无NAT
#define NAT_TYPE_SRC 1         // 源NAT
#define NAT_TYPE_DEST 2        // 目标NAT

// ----- netlink通信相关定义 -----
#include <linux/netlink.h>

#define NETLINK_MYFW 17        // 自定义netlink协议号

// netlink通信函数声明
struct sock *netlink_init(void);
void netlink_release(void);
int nlSend(unsigned int pid, void *data, unsigned int len);

// ----- 应用交互相关函数声明 -------
int dealAppMessage(unsigned int pid, void *msg, unsigned int len);
void* formAllIPRules(unsigned int *len);
struct IPRule * addIPRuleToChain(char after[], struct IPRule rule);
struct IPRule * changeIPRuleOfChain(int key, struct IPRule rule);
int delIPRuleFromChain(char name[]);
void* formAllIPLogs(unsigned int num, unsigned int *len);
void* formAllConns(unsigned int *len);
struct NATRecord * addNATRuleToChain(struct NATRecord rule);
int delNATRuleFromChain(int num);
void* formAllNATRules(unsigned int *len);

// ----- netfilter相关定义 -----
#define MAX_LOG_LEN 1000       // 最大日志缓存长度

// netfilter相关函数声明
struct IPRule matchIPRules(struct sk_buff *skb, int *isMatch);
int addLog(struct IPLog log);
int addLogBySKB(unsigned int action, struct sk_buff *skb);

// ----- 连接池相关定义 --------
#include <linux/rbtree.h>

#define CONN_NEEDLOG 0x10      // 需要记录日志标志
#define CONN_MAX_SYM_NUM 3     // 连接标识符最大数量
#define CONN_EXPIRES 7         // 连接超时时间(秒)
#define CONN_NAT_TIMES 10      // NAT连接超时时间倍率
#define CONN_ROLL_INTERVAL 5   // 定期清理间隔(秒)

typedef unsigned int conn_key_t[CONN_MAX_SYM_NUM]; // 连接标识符类型定义

// 连接节点结构体定义
typedef struct connNode {
    struct rb_node node;       // 红黑树节点
    conn_key_t key;            // 连接标识符
    unsigned long expires;      // 超时时间
    u_int8_t protocol;         // 协议类型
    u_int8_t needLog;          // 是否需要记录日志

    struct NATRecord nat;      // NAT记录
    int natType;               // NAT类型
}connNode;

#define timeFromNow(plus) (jiffies + ((plus) * HZ))

// 连接池相关函数声明
void conn_init(void);
void conn_exit(void);
struct connNode *hasConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport);
struct connNode *addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t proto, u_int8_t log);
bool matchOneRule(struct IPRule *rule, unsigned int sip, unsigned int dip, unsigned short sport, unsigned int dport, u_int8_t proto);
int eraseConnRelated(struct IPRule rule);
void addConnExpires(struct connNode *node, unsigned int plus);

// ----- NAT操作相关函数声明 ----
int setConnNAT(struct connNode *node, struct NATRecord record, int natType);
struct NATRecord *matchNATRule(unsigned int sip, unsigned int dip, int *isMatch);
unsigned short getNewNATPort(struct NATRecord rule);
struct NATRecord genNATRecord(unsigned int preIP, unsigned int afterIP, unsigned short prePort, unsigned short afterPort);

#endif