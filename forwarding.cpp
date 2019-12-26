#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
	// 1、检验校验和
	int head_len = (packet[0] & 0xf) << 2;   // 获取IP头长度（单位是字节）
	int in_checksum = (packet[10] << 8)+ packet[11];     // 输入的校验和
	int checksum = 0;   // 即将计算出的校验和
	for(int i = 0; i < head_len; i += 2)  // 计算IP头每16位的和
		checksum += ((packet[i] << 8) + packet[i + 1]);
	while (checksum & 0xffff0000) // 确保和的高16位是0
		checksum = (checksum & 0xffff) + (checksum  >> 16);
	checksum = (~checksum) & 0xffff;    // 取反后取低16位
	if(checksum) return false;   // 校验结果不为0,直接return false
	// 2、更新TTL
	int origin_ttl = packet[8]; // 原来的校验和
	packet[8] = (origin_ttl - 1) & 0xff;
	// 3、更新校验和，用增量更新法：HC' = HC + m + ~m',注意移位优先级，还有16位取反有坑，以及~m是求补，不是单纯取反
	int m = (origin_ttl << 8) + packet[9];          // 原来的16位加数
 	int new_m = (packet[8] << 8) + packet[9];   // 变化后的16位加数
	int new_checksum = in_checksum + m + ~new_m + 1;  // 新的校验和
	if(new_checksum == 0xffff) new_checksum ++;   // 特判校验和为0xffff的情况
	packet[10] = new_checksum >> 8;    // 把新校验和填入packet中
	packet[11] = new_checksum & 0xff;
	return true;   // IP有效
}
