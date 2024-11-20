#include "helper.h"

extern unsigned int DEFAULT_ACTION;

// 发送消息到应用程序
int sendMsgToApp(unsigned int pid, const char *msg) {
    void* mem;
    unsigned int rspLen;
    struct KernelResponseHeader *rspH;
    rspLen = sizeof(struct KernelResponseHeader) + strlen(msg) + 1;
    mem = kzalloc(rspLen, GFP_ATOMIC);
    if(mem == NULL) {
        printk(KERN_WARNING "[防火墙内核] 发送消息到应用程序时内存分配失败。\n");
        return 0;
    }
    rspH = (struct KernelResponseHeader *)mem;
    rspH->bodyTp = RSP_MSG;
    rspH->arrayLen = strlen(msg);
    memcpy(mem+sizeof(struct KernelResponseHeader), msg, strlen(msg));
    nlSend(pid, mem, rspLen);
    kfree(mem);
    return rspLen;
}

// 处理设置动作
void dealWithSetAction(unsigned int action) {
    if(action != NF_ACCEPT) {
        struct IPRule rule = {
            .smask = 0,
            .dmask = 0,
            .sport = -1,
            .dport = -1
        }; // 清除全部连接
        eraseConnRelated(rule);
    }
}

// 处理应用程序消息
int dealAppMessage(unsigned int pid, void *msg, unsigned int len) {
    struct APPRequest *req;
    struct KernelResponseHeader *rspH;
    void* mem;
    unsigned int rspLen = 0;
    req = (struct APPRequest *) msg;
    switch (req->tp)
    {
    case REQ_GETAllIPLogs:
        mem = formAllIPLogs(req->msg.num, &rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "[防火墙内核] 获取所有IP日志时失败。\n");
            sendMsgToApp(pid, "获取所有日志失败。");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_GETAllConns:
        mem = formAllConns(&rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "[防火墙内核] 获取所有连接时失败。\n");
            sendMsgToApp(pid, "获取所有连接失败。");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_GETAllIPRules:
        mem = formAllIPRules(&rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "[防火墙内核] 获取所有IP规则时失败。\n");
            sendMsgToApp(pid, "获取所有规则失败。");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_ADDIPRule:
        if(addIPRuleToChain(req->ruleName, req->msg.ipRule)==NULL) {
            rspLen = sendMsgToApp(pid, "失败：没有该规则或请重试。");
            printk("[防火墙内核] 添加规则失败。\n");
        } else {
            rspLen = sendMsgToApp(pid, "成功。");
            printk("[防火墙内核] 成功添加一条规则：%s。\n", req->msg.ipRule.name);
        }
        break;
    case REQ_CHANGEIPRule:
        if(changeIPRuleOfChain(req->num, req->msg.ipRule)==NULL) {
            rspLen = sendMsgToApp(pid, "失败：没有该规则或请重试。");
            printk("[防火墙内核] 修改规则失败。\n");
        } else {
            rspLen = sendMsgToApp(pid, "成功。");
            printk("[防火墙内核] 成功修改一条规则：%s。\n", req->msg.ipRule.name);
        }
        break;
    case REQ_DELIPRule:
        rspLen = sizeof(struct KernelResponseHeader);
        rspH = (struct KernelResponseHeader *)kzalloc(rspLen, GFP_KERNEL);
        if(rspH == NULL) {
            printk(KERN_WARNING "[防火墙内核] 内存分配失败。\n");
            sendMsgToApp(pid, "响应生成失败，但删除可能成功。");
            break;
        }
        rspH->bodyTp = RSP_Only_Head;
        rspH->arrayLen = delIPRuleFromChain(req->ruleName);
        printk("[防火墙内核] 成功删除 %d 条规则。\n", rspH->arrayLen);
        nlSend(pid, rspH, rspLen);
        kfree(rspH);
        break;
    case REQ_GETNATRules:
        mem = formAllNATRules(&rspLen);
        if(mem == NULL) {
            printk(KERN_WARNING "[防火墙内核] 获取所有NAT规则时失败。\n");
            sendMsgToApp(pid, "获取所有NAT规则失败。");
            break;
        }
        nlSend(pid, mem, rspLen);
        kfree(mem);
        break;
    case REQ_ADDNATRule:
        if(addNATRuleToChain(req->msg.natRule)==NULL) {
            rspLen = sendMsgToApp(pid, "失败：请重试。");
            printk("[防火墙内核] 添加NAT规则失败。\n");
        } else {
            rspLen = sendMsgToApp(pid, "成功。");
            printk("[防火墙内核] 成功添加一条NAT规则。\n");
        }
        break;
    case REQ_DELNATRule:
        rspLen = sizeof(struct KernelResponseHeader);
        rspH = (struct KernelResponseHeader *)kzalloc(rspLen, GFP_KERNEL);
        if(rspH == NULL) {
            printk(KERN_WARNING "[防火墙内核] 内存分配失败。\n");
            sendMsgToApp(pid, "响应生成失败，但删除可能成功。");
            break;
        }
        rspH->bodyTp = RSP_Only_Head;
        rspH->arrayLen = delNATRuleFromChain(req->msg.num);
        printk("[防火墙内核] 成功删除 %d 条NAT规则。\n", rspH->arrayLen);
        nlSend(pid, rspH, rspLen);
        kfree(rspH);
        break;
    case REQ_SETAction:
        if(req->msg.defaultAction == NF_ACCEPT) {
            DEFAULT_ACTION = NF_ACCEPT;
            rspLen = sendMsgToApp(pid, "设置默认动作为接受。");
            printk("[防火墙内核] 设置默认动作为NF_ACCEPT。\n");
        } else {
            DEFAULT_ACTION = NF_DROP;
            rspLen = sendMsgToApp(pid, "设置默认动作为丢弃。");
            printk("[防火墙内核] 设置默认动作为NF_DROP。\n");
        }
        dealWithSetAction(DEFAULT_ACTION);
        break;
    default:
        rspLen = sendMsgToApp(pid, "无此请求。");
        break;
    }
    return rspLen;
}