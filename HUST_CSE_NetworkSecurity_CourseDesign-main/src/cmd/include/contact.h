#ifndef _HELPER_H
#define _HELPER_H

#include "common.h"

/**
 * 处理来自内核的响应消息
 * 根据响应类型和错误码进行相应处理
 * 支持以下响应类型:
 * - RSP_Only_Head: 仅包含头部信息的响应
 * - RSP_MSG: 文本消息响应
 * - RSP_IPRules: IP规则列表响应
 * - RSP_NATRules: NAT规则列表响应  
 * - RSP_IPLogs: IP日志列表响应
 * - RSP_ConnLogs: 连接日志列表响应
 * @param rsp 内核响应结构体
 */
void dealResponseAtCmd(struct KernelResponse rsp);

#endif