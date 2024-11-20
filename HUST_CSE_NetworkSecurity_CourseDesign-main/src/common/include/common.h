#ifndef _COMMON_APP_H
#define _COMMON_APP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>

// ---- APP 与 Kernel 通用协议 ------
#define MAXRuleNameLen 11

#define REQ_GETAllIPRules 1 // 获取所有IP规则
#define REQ_ADDIPRule 2 // 添加IP规则
#define REQ_CHANGEIPRule 16 // 修改IP规则
#define REQ_DELIPRule 3 // 删除IP规则
#define REQ_SETAction 4 // 设置动作
#define REQ_GETAllIPLogs 5 // 获取所有IP日志
#define REQ_GETAllConns 6 // 获取所有连接
#define REQ_ADDNATRule 7 // 添加NAT规则
#define REQ_DELNATRule 8 // 删除NAT规则
#define REQ_GETNATRules 9 // 获取NAT规则

#define RSP_Only_Head 10 // 仅有头部的响应
#define RSP_MSG 11 // 消息响应
#define RSP_IPRules 12  // IP规则响应，body为IPRule[]
#define RSP_IPLogs 13   // IP日志响应，body为IPlog[]
#define RSP_NATRules 14 // NAT规则响应，body为NATRecord[]
#define RSP_ConnLogs 15 // 连接日志响应，body为ConnLog[]

struct IPRule {
    char name[MAXRuleNameLen+1]; // 规则名称
    unsigned int saddr; // 源地址
    unsigned int smask; // 源地址掩码
    unsigned int daddr; // 目的地址
    unsigned int dmask; // 目的地址掩码
    unsigned int sport; // 源端口范围 高2字节为最小 低2字节为最大
    unsigned int dport; // 目的端口范围 同上
    u_int8_t protocol; // 协议类型
    unsigned int action; // 动作
    unsigned int log; // 日志
    struct IPRule* nx; // 下一个IP规则指针
};

struct IPLog {
    long tm; // 时间戳
    unsigned int saddr; // 源地址
    unsigned int daddr; // 目的地址
    unsigned short sport; // 源端口
    unsigned short dport; // 目的端口
    u_int8_t protocol; // 协议类型
    unsigned int len; // 数据包长度
    unsigned int action; // 动作
    struct IPLog* nx; // 下一个IP日志指针
};

struct NATRecord { // NAT 记录或规则(源IP端口转换)
    unsigned int saddr; // 记录：原始IP | 规则：原始源IP
    unsigned int smask; // 记录：无作用  | 规则：原始源IP掩码
    unsigned int daddr; // 记录：转换后的IP | 规则：NAT 源IP

    unsigned short sport; // 记录：原始端口 | 规则：最小端口范围
    unsigned short dport; // 记录：转换后的端口 | 规则：最大端口范围
    unsigned short nowPort; // 记录：当前使用端口 | 规则：无作用
    struct NATRecord* nx; // 下一个NAT记录指针
};

struct ConnLog {
    unsigned int saddr; // 源地址
    unsigned int daddr; // 目的地址
    unsigned short sport; // 源端口
    unsigned short dport; // 目的端口
    u_int8_t protocol; // 协议类型
    int natType; // NAT类型
    struct NATRecord nat; // NAT记录
};

struct APPRequest {
    unsigned int tp; // 请求类型
    char ruleName[MAXRuleNameLen+1]; // 规则名称
    int num; // 数量
    union {
        struct IPRule ipRule; // IP规则
        struct NATRecord natRule; // NAT规则
        unsigned int defaultAction; // 默认动作
        unsigned int num; // 数量
    } msg; // 消息
};

struct KernelResponseHeader {
    unsigned int bodyTp; // 响应体类型
    unsigned int arrayLen; // 数组长度
};

#define NAT_TYPE_NO 0 // 无NAT
#define NAT_TYPE_SRC 1 // 源NAT
#define NAT_TYPE_DEST 2 // 目的NAT

// ----- 上层应用专用 ------
#define uint8_t unsigned char
#define NETLINK_MYFW 17
#define MAX_PAYLOAD (1024 * 256)

#define ERROR_CODE_EXIT -1 // 退出错误码
#define ERROR_CODE_EXCHANGE -2 // 与内核交换信息失败
#define ERROR_CODE_WRONG_IP -11 // 错误的IP格式
#define ERROR_CODE_NO_SUCH_RULE -12 // 无此规则

/** 
 * @brief 内核回应包
 */
struct KernelResponse {
    int code; // <0 代表请求失败，失败码; >=0 代表body长度
    void *data; // 回应包指针，记得free
    struct KernelResponseHeader *header; // 不要free；指向data中的头部
    void *body; // 不要free；指向data中的Body
};

/**
 * @brief 与内核交换数据
 * @param smsg: 发送的消息
 * @param slen: 发送消息的长度
 * @return KernelResponse: 接收到的回应，其中data字段记得free
 */
struct KernelResponse exchangeMsgK(void *smsg, unsigned int slen);

// ----- 与内核交互函数 -----

struct KernelResponse addFilterRule(char *after,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action); // 新增一条过滤规则，其中，sport/dport为端口范围：高2字节为最小 低2字节为最大
struct KernelResponse changeFilterRule(int key,char *name,char *sip,char *dip,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned int log,unsigned int action); // 修改一条过滤规则，其中，sport/dport为端口范围：高2字节为最小 低2字节为最大
struct KernelResponse delFilterRule(char *name); // 删除过滤规则
struct KernelResponse getAllFilterRules(void); // 获取所有过滤规则
struct KernelResponse addNATRule(char *sip,char *natIP,unsigned short minport,unsigned short maxport); // 添加NAT规则
struct KernelResponse delNATRule(int num); // 删除NAT规则
struct KernelResponse getAllNATRules(void); // 获取所有NAT规则
struct KernelResponse setDefaultAction(unsigned int action); // 设置默认动作
struct KernelResponse getLogs(unsigned int num); // num=0时，获取所有日志
struct KernelResponse getAllConns(void); // 获取所有连接

// ----- 一些工具函数 ------

int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask); // 将IP字符串转换为IP整数
int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr); // 将IP整数转换为IP字符串
int IPint2IPstrNoMask(unsigned int ip, char *ipStr); // 将IP整数转换为无掩码的IP字符串
int IPint2IPstrWithPort(unsigned int ip, unsigned short port, char *ipStr); // 将IP整数和端口转换为IP字符串

#endif