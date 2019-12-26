#include <stdint.h>
#include <stdlib.h>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
	// 1、IP头信息获取
	int head_len = (packet[0] & 0xf) << 2;   // 获取IP头长度（单位是字节）
	int in_checksum = (packet[10] << 8)+ packet[11];     // 输入的校验和
	// 2、对IP头进行16位分组与求和
	int checksum = 0;   // 即将计算出的校验和
	for(int i = 0; i < head_len; i += 2)  // 计算IP头每16位的和
		checksum += ((packet[i] << 8) + packet[i + 1]);
	// 3、处理结果的高16位
	while (checksum & 0xffff0000) // 确保和的高16位是0
		checksum = (checksum & 0xffff) + (checksum  >> 16);
	// 4、取反码
	checksum = (~checksum) & 0xffff;    // 取反后取低16位
	// 5、判断
	return !checksum;  // 若上述结果为0,说明校验和正确；否则返回false   
}