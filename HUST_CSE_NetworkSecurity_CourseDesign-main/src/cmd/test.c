#include "test.h"
#include <stdio.h>
#include <string.h>
#include <linux/netfilter.h>

// 测试过滤规则
void test_filter_rules() {
    printf("\n=== 测试过滤规则 ===\n");
    struct KernelResponse rsp;
    
    // 测试添加TCP规则
    printf("添加TCP规则...\n");
    rsp = addFilterRule("", "test_tcp", "192.168.1.0/24", "10.0.0.0/24", 
                       (80 << 16) | 80,  // 源端口80
                       (443 << 16) | 443, // 目标端口443
                       IPPROTO_TCP, 1, NF_ACCEPT);
    printf("结果: %s\n", rsp.code < 0 ? "失败" : "成功");

    // 测试添加UDP规则
    printf("\n添加UDP规则...\n");
    rsp = addFilterRule("test_tcp", "test_udp", "172.16.0.0/16", "any", 
                       0xFFFFu,  // 任意源端口
                       (53 << 16) | 53,  // DNS端口
                       IPPROTO_UDP, 1, NF_ACCEPT);
    printf("结果: %s\n", rsp.code < 0 ? "失败" : "成功");

    // 显示当前规则
    printf("\n当前过滤规则列表:\n");
    rsp = getAllFilterRules();
    if(rsp.code >= 0) {
        showRules((struct IPRule*)rsp.body, rsp.header->arrayLen);
    }

    // 清理测试规则
    printf("\n清理测试规则...\n");
    delFilterRule("test_tcp");
    delFilterRule("test_udp");
}

// 测试NAT规则
void test_nat_rules() {
    printf("\n=== 测试NAT规则 ===\n");
    struct KernelResponse rsp;
    
    // 添加SNAT规则
    printf("添加SNAT规则...\n");
    rsp = addNATRule("192.168.0.0/24", "1.2.3.4", 10000, 20000);
    printf("结果: %s\n", rsp.code < 0 ? "失败" : "成功");

    // 显示当前NAT规则
    printf("\n当前NAT规则列表:\n");
    rsp = getAllNATRules();
    if(rsp.code >= 0) {
        showNATRules((struct NATRecord*)rsp.body, rsp.header->arrayLen);
    }

    // 清理测试规则
    printf("\n清理测试规则...\n");
    delNATRule(0);  // 删除第一条规则
}

// 测试日志功能
void test_logs() {
    printf("\n=== 测试日志功能 ===\n");
    struct KernelResponse rsp = getLogs(5);  // 获取最近5条日志
    
    if(rsp.code >= 0) {
        printf("最近5条日志记录:\n");
        showLogs((struct IPLog*)rsp.body, rsp.header->arrayLen);
    } else {
        printf("获取日志失败\n");
    }
}

// 测试连接状态
void test_connections() {
    printf("\n=== 测试连接状态 ===\n");
    struct KernelResponse rsp = getAllConns();
    
    if(rsp.code >= 0) {
        printf("当前活动连接:\n");
        showConns((struct ConnLog*)rsp.body, rsp.header->arrayLen);
    } else {
        printf("获取连接状态失败\n");
    }
} 