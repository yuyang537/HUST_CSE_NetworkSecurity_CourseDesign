#include "common.h"

/**
 * 将IP地址字符串转换为整数形式
 * @param ipStr IP地址字符串,格式为"x.x.x.x/x"或"x.x.x.x"
 * @param ip 输出参数,转换后的IP地址整数
 * @param mask 输出参数,转换后的子网掩码整数
 * @return 0:成功, -1:格式错误, -2:IP地址段错误
 */
int IPstr2IPint(const char *ipStr, unsigned int *ip, unsigned int *mask){
	// 初始化变量
	int p = -1, count = 0;
	unsigned int len = 0, tmp = 0, r_mask = 0, r_ip = 0,i;
	// 检查IP字符串是否只包含数字、点和斜杠
	for(i = 0; i < strlen(ipStr); i++){
		if(!(ipStr[i]>='0' && ipStr[i]<='9') && ipStr[i]!='.' && ipStr[i]!='/') {
			return -1; // IP地址格式错误
		}
	}
	// 解析子网掩码长度
	for(i = 0; i < strlen(ipStr); i++){
        if(p != -1){
            len *= 10;
            len += ipStr[i] - '0';
        }
        else if(ipStr[i] == '/')
            p = i;
    }
	if(len > 32 || (p>=0 && p<7)) {
		return -1; // 子网掩码长度错误
	}
    if(p != -1){
        if(len)
            r_mask = 0xFFFFFFFF << (32 - len);
    }
    else r_mask = 0xFFFFFFFF;
	// 解析IP地址
    for(i = 0; i < (p>=0 ? p : strlen(ipStr)); i++){
        if(ipStr[i] == '.'){
            r_ip = r_ip | (tmp << (8 * (3 - count)));
            tmp = 0;
            count++;
            continue;
        }
        tmp *= 10;
        tmp += ipStr[i] - '0';
		if(tmp>256 || count>3)
			return -2; // IP地址段超出范围
    }
    r_ip = r_ip | tmp;
	*ip = r_ip;
	*mask = r_mask;
    return 0;
}

/**
 * 将IP地址整数转换为带掩码的字符串形式
 * @param ip IP地址整数
 * @param mask 子网掩码整数
 * @param ipStr 输出参数,转换后的IP地址字符串
 * @return 0:成功, -1:参数错误
 */
int IPint2IPstr(unsigned int ip, unsigned int mask, char *ipStr) {
    unsigned int i,ips[4],maskNum = 32;
    if(ipStr == NULL) {
        return -1; // 输出缓冲区为空
    }
	if(mask == 0)
		maskNum = 0;
	else {
		while((mask & 1u) == 0) {
                	maskNum--;
                	mask >>= 1;
        	}
	}
    for(i=0;i<4;i++) {
        ips[i] = ((ip >> ((3-i)*8)) & 0xFFU);
    }
	sprintf(ipStr, "%u.%u.%u.%u/%u", ips[0], ips[1], ips[2], ips[3], maskNum);
	return 0;
}

/**
 * 将IP地址整数转换为不带掩码的字符串形式
 * @param ip IP地址整数
 * @param ipStr 输出参数,转换后的IP地址字符串
 * @return 0:成功, -1:参数错误
 */
int IPint2IPstrNoMask(unsigned int ip, char *ipStr) {
    unsigned int i,ips[4];
    if(ipStr == NULL) {
        return -1; // 输出缓冲区为空
    }
    for(i=0;i<4;i++) {
        ips[i] = ((ip >> ((3-i)*8)) & 0xFFU);
    }
	sprintf(ipStr, "%u.%u.%u.%u", ips[0], ips[1], ips[2], ips[3]);
	return 0;
}

/**
 * 将IP地址整数和端口转换为字符串形式
 * @param ip IP地址整数
 * @param port 端口号
 * @param ipStr 输出参数,转换后的IP地址和端口字符串
 * @return 0:成功, -1:参数错误
 */
int IPint2IPstrWithPort(unsigned int ip, unsigned short port, char *ipStr) {
    if(port == 0) {
        return IPint2IPstrNoMask(ip, ipStr);
    }
    unsigned int i,ips[4];
    if(ipStr == NULL) {
        return -1; // 输出缓冲区为空
    }
    for(i=0;i<4;i++) {
        ips[i] = ((ip >> ((3-i)*8)) & 0xFFU);
    }
	sprintf(ipStr, "%u.%u.%u.%u:%u", ips[0], ips[1], ips[2], ips[3], port);
	return 0;
}