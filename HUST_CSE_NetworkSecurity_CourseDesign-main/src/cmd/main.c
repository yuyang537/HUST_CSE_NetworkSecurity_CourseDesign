#include "contact.h"

// 新增过滤规则时的用户交互
struct KernelResponse cmdAddRule() {
    struct KernelResponse empty;
    char after[MAXRuleNameLen+1],name[MAXRuleNameLen+1],saddr[25],daddr[25],sport[15],dport[15],protoS[6];
    unsigned short sportMin,sportMax,dportMin,dportMax;
    unsigned int action = NF_DROP, log = 0, proto, i;
    empty.code = ERROR_CODE_EXIT;
    // 前序规则名
    printf("请输入在哪条规则之后添加[直接回车表示添加到开头]: ");
    for(i=0;;i++) {
        if(i>MAXRuleNameLen) {
            printf("[防火墙内核] 规则名称过长\n");
            return empty;
        }
        after[i] = getchar();
        if(after[i] == '\n' || after[i] == '\r') {
            after[i] = '\0';
            break;
        }
    }
    // 规则名
    printf("请输入规则名称[最大长度=%d]: ", MAXRuleNameLen);
    scanf("%s",name);
    if(strlen(name)==0 || strlen(name)>MAXRuleNameLen) {
        printf("[防火墙内核] 规则名称长度不合法\n");
        return empty;
    }
    // 源IP
    printf("请输入源IP地址和掩码[格式如 127.0.0.1/16]: ");
    scanf("%s",saddr);
    // 源端口
    printf("请输入源端口范围[格式如 8080-8031 或 any]: ");
    scanf("%s",sport);
    if(strcmp(sport, "any") == 0) {
        sportMin = 0,sportMax = 0xFFFFu;
    } else {
        sscanf(sport,"%hu-%hu",&sportMin,&sportMax);
    }
    if(sportMin > sportMax) {
        printf("[防火墙内核] 端口范围错误:最小端口号大于最大端口号\n");
        return empty;
    }
    // 目的IP
    printf("请输入目的IP地址和掩码[格式如 127.0.0.1/16]: ");
    scanf("%s",daddr);
    // 目的端口
    printf("请输入目的端口范围[格式如 8080-8031 或 any]: ");
    scanf("%s",dport);
    if(strcmp(dport, "any") == 0) {
        dportMin = 0,dportMax = 0xFFFFu;
    } else {
        sscanf(dport,"%hu-%hu",&dportMin,&dportMax);
    }
    if(dportMin > dportMax) {
        printf("[防火墙内核] 端口范围错误:最小端口号大于最大端口号\n");
        return empty;
    }
    // 协议
    printf("请输入协议类型[TCP/UDP/ICMP/any]: ");
    scanf("%s",protoS);
    if(strcmp(protoS,"TCP")==0)
        proto = IPPROTO_TCP;
    else if(strcmp(protoS,"UDP")==0)
        proto = IPPROTO_UDP;
    else if(strcmp(protoS,"ICMP")==0)
        proto = IPPROTO_ICMP;
    else if(strcmp(protoS,"any")==0)
        proto = IPPROTO_IP;
    else {
        printf("[防火墙内核] 不支持该协议类型\n");
        return empty;
    }
    // 动作
    printf("请输入处理动作[1表示通过,0表示拦截]: ");
    scanf("%d",&action);
    // 是否记录日志
    printf("是否记录日志[1表示记录,0表示不记录]: ");
    scanf("%u",&log);
    printf("规则添加结果:\n");
    return addFilterRule(after,name,saddr,daddr,
        (((unsigned int)sportMin << 16) | (((unsigned int)sportMax) & 0xFFFFu)),
        (((unsigned int)dportMin << 16) | (((unsigned int)dportMax) & 0xFFFFu)),proto,log,action);
}

// 修改过滤规则时的用户交互
struct KernelResponse cmdChangeRule() {
    struct KernelResponse empty;
    char name[MAXRuleNameLen+1],saddr[25],daddr[25],sport[15],dport[15],protoS[6];
    unsigned short sportMin,sportMax,dportMin,dportMax;
    unsigned int action = NF_DROP, log = 0, proto, i, key = 0;
    empty.code = ERROR_CODE_EXIT;
    // 规则序号（以1开始）
    printf("请输入要修改的规则序号[从1开始]: ");
    scanf("%d", &key);
    // 规则名
    printf("请输入新的规则名称[最大长度=%d,输入-1表示不修改]: ", MAXRuleNameLen);
    scanf("%s",name);
    if(strlen(name)==0 || strlen(name)>MAXRuleNameLen) {
        printf("[防火墙内核] 规则名称长度不合法\n");
        return empty;
    }
    // 源IP
    printf("请输入新的源IP地址和掩码[格式如 127.0.0.1/16,输入-1表示不修改]: ");
    scanf("%s",saddr);
    // 源端口
    printf("请输入新的源端口范围[格式如 8080-8031 或 any,输入-1表示不修改]: ");
    scanf("%s",sport);
    if(strcmp(sport, "-1") == 0){
        sportMin = 0, sportMax= 0;
    } else if(strcmp(sport, "any") == 0) {
        sportMin = 0,sportMax = 0xFFFFu;
    } else {
        sscanf(sport,"%hu-%hu",&sportMin,&sportMax);
    }
    if(sportMin > sportMax) {
        printf("[防火墙内核] 端口范围错误:最小端口号大于最大端口号\n");
        return empty;
    }
    // 目的IP
    printf("请输入新的目的IP地址和掩码[格式如 127.0.0.1/16,输入-1表示不修改]: ");
    scanf("%s",daddr);
    // 目的端口
    printf("请输入新的目的端口范围[格式如 8080-8031 或 any,输入-1表示不修改]: ");
    scanf("%s",dport);
    if(strcmp(sport, "-1") == 0){
        dportMin=0,dportMax=0;
    } else if(strcmp(dport, "any") == 0) {
        dportMin = 0,dportMax = 0xFFFFu;
    } else {
        sscanf(dport,"%hu-%hu",&dportMin,&dportMax);
    }
    if(dportMin > dportMax) {
        printf("[防火墙内核] 端口范围错误:最小端口号大于最大端口号\n");
        return empty;
    }
    // 协议
    printf("请输入新的协议类型[TCP/UDP/ICMP/any,输入-1表示不修改]: ");
    scanf("%s",protoS);
    if(strcmp(protoS,"TCP")==0)
        proto = IPPROTO_TCP;
    else if(strcmp(protoS,"UDP")==0)
        proto = IPPROTO_UDP;
    else if(strcmp(protoS,"ICMP")==0)
        proto = IPPROTO_ICMP;
    else if(strcmp(protoS,"any")==0)
        proto = IPPROTO_IP;
    else if(strcmp(protoS, "-1")==0)
        proto = 255;
    else {
        printf("[防火墙内核] 不支持该协议类型\n");
        return empty;
    }
    // 动作
    printf("请输入新的处理动作[1表示通过,0表示拦截,2表示不修改]: ");
    scanf("%d",&action);
    // 是否记录日志
    printf("是否记录日志[1表示记录,0表示不记录,2表示不修改]: ");
    scanf("%u",&log);
    printf("规则修改结果:\n");
    return changeFilterRule(key,name,saddr,daddr,
        (((unsigned int)sportMin << 16) | (((unsigned int)sportMax) & 0xFFFFu)),
        (((unsigned int)dportMin << 16) | (((unsigned int)dportMax) & 0xFFFFu)),proto,log,action);
}

struct KernelResponse cmdAddNATRule() {
    struct KernelResponse empty;
    char saddr[25],daddr[25],port[15];
    unsigned short portMin,portMax;
    empty.code = ERROR_CODE_EXIT;
    printf("目前仅支持源地址NAT转换\n");
    // 源IP
    printf("请输入源IP地址和掩码[格式如 127.0.0.1/16]: ");
    scanf("%s",saddr);
    // NAT IP
    printf("请输入NAT转换后的IP地址[格式如 192.168.80.139]: ");
    scanf("%s",daddr);
    // 目的端口
    printf("请输入NAT端口范围[格式如 10000-30000 或 any]: ");
    scanf("%s",port);
    if(strcmp(port, "any") == 0) {
        portMin = 0,portMax = 0xFFFFu;
    } else {
        sscanf(port,"%hu-%hu",&portMin,&portMax);
    }
    if(portMin > portMax) {
        printf("[防火墙内核] 端口范围错误:最小端口号大于最大端口号\n");
        return empty;
    }
    return addNATRule(saddr,daddr,portMin,portMax);
}

void wrongCommand() {
    printf("[防火墙内核] 命令格式错误\n");
    printf("使用方法: uapp <命令> <子命令> [选项]\n");
    printf("命令列表: rule <add | del | ls | change | default> [要删除的规则名]\n");
    printf("          nat  <add | del | ls> [要删除的规则序号]\n");
    printf("          ls   <rule | nat | log | connect>\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    if(argc<3) { // 需要3个或以上参数
        wrongCommand();
        return 0;
    }
    struct KernelResponse rsp;
    rsp.code = ERROR_CODE_EXIT;
    // 过滤规则相关
    if(strcmp(argv[1], "rule")==0 || argv[1][0] == 'r') {
        if(strcmp(argv[2], "ls")==0 || strcmp(argv[2], "list")==0) {
        // 列出所有过滤规则
            rsp = getAllFilterRules();
        } else if(strcmp(argv[2], "del")==0) {
        // 删除过滤规则
            if(argc < 4)
                printf("[防火墙内核] 请在选项中指定要删除的规则名称\n");
            else if(strlen(argv[3])>MAXRuleNameLen)
                printf("[防火墙内核] 规则名称过长\n");
            else
                rsp = delFilterRule(argv[3]);
        } else if(strcmp(argv[2], "add")==0) {
        // 添加过滤规则
            rsp = cmdAddRule();
        } else if(strcmp(argv[2], "change")==0) {
        // 修改指定规则
            rsp = cmdChangeRule();
        } else if(strcmp(argv[2], "default")==0) {
        // 设置默认规则
            if(argc < 4)
                printf("[防火墙内核] 请在选项中指定默认动作\n");
            else if(strcmp(argv[3], "accept")==0)
                rsp = setDefaultAction(NF_ACCEPT);
            else if(strcmp(argv[3], "drop")==0)
                rsp = setDefaultAction(NF_DROP);
            else
                printf("[防火墙内核] 不支持该动作,仅支持\"accept\"或\"drop\"\n");
        } else 
            wrongCommand();
    } else if(strcmp(argv[1], "nat")==0 || argv[1][0] == 'n') {
        if(strcmp(argv[2], "ls")==0 || strcmp(argv[2], "list")==0) {
        // 列出所有NAT规则
            rsp = getAllNATRules();
        } else if(strcmp(argv[2], "del")==0) {
        // 删除NAT规则
            if(argc < 4)
                printf("[防火墙内核] 请在选项中指定要删除的规则序号\n");
            else {
                int num;
                sscanf(argv[3], "%d", &num);
                rsp = delNATRule(num);
            }
        } else if(strcmp(argv[2], "add")==0) {
        // 添加NAT规则
            rsp = cmdAddNATRule();
        } else {
            wrongCommand();
        }
    } else if(strcmp(argv[1], "ls")==0 || argv[1][0] == 'l') {
    // 展示相关
        if(strcmp(argv[2],"log")==0 || argv[2][0] == 'l') {
        // 过滤日志
            unsigned int num = 0;
            if(argc > 3)
                sscanf(argv[3], "%u", &num);
            rsp = getLogs(num);
        } else if(strcmp(argv[2],"con")==0 || argv[2][0] == 'c') {
        // 连接状态
            rsp = getAllConns();
        } else if(strcmp(argv[2],"rule")==0 || argv[2][0] == 'r') {
        // 已有过滤规则
            rsp = getAllFilterRules();
        } else if(strcmp(argv[2],"nat")==0 || argv[2][0] == 'n') {
        // 已有NAT规则
            rsp = getAllNATRules();
        } else
            wrongCommand();
    } else if(strcmp(argv[1], "test")==0 || argv[1][0] == 't') {
        if(argc < 3) {
            printf("请指定测试类型:\n");
            printf("  rule  - 测试过滤规则\n");
            printf("  nat   - 测试NAT规则\n");
            printf("  log   - 测试日志功能\n");
            printf("  conn  - 测试连接状态\n");
            printf("  all   - 执行所有测试\n");
            return 0;
        }
        
        if(strcmp(argv[2], "rule")==0) {
            test_filter_rules();
        } else if(strcmp(argv[2], "nat")==0) {
            test_nat_rules(); 
        } else if(strcmp(argv[2], "log")==0) {
            test_logs();
        } else if(strcmp(argv[2], "conn")==0) {
            test_connections();
        } else if(strcmp(argv[2], "all")==0) {
            printf("开始执行全部测试...\n\n");
            test_filter_rules();
            test_nat_rules();
            test_logs(); 
            test_connections();
            printf("\n全部测试完成\n");
        } else {
            wrongCommand();
        }
    } else 
        wrongCommand();
    dealResponseAtCmd(rsp);
}
