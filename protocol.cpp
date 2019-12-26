#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include<stdio.h>
#include <arpa/inet.h> 
/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
	int total_length = (packet[2] << 8) + packet[3];
	int head_len = (packet[0] & 0xf) << 2;   // 获取IP头长度（单位是字节）
	int ip_version = packet[9];  // IP传输协议
	// printf("%d\n",total_length);
	if(total_length != len || ip_version != 17) return false;	 // 总长度不对，或者传输格式不是UDP，对应上述第一条判断
	int rip_start = head_len + 8;   // rip包起始位置,UDP报头总是8个字节
	int version = packet[rip_start + 1]; 
	uint8_t command = packet[rip_start];   // 1:request, 2: response
	// printf("command = %x\n",command);
	int zero = (packet[rip_start + 2] << 8) + packet[rip_start + 3];
	if(version != 2 || zero != 0 || (command != 1 && command != 2)) return false;  // 对应上述第二条判断
	// 遍历每个表项
	uint32_t enrty_num = (total_length - head_len - 8 - 4) / 20;  // 一个rip_entry本身长度为20，已知IP总长，IP头长，UDP头长和RIP头长，剩下都是entry 
	output->numEntries = enrty_num;
	// printf("htonl(command) = %x\n",htonl(command));
	// output->command = htonl(command) & 0xff;
	output->command = command;
	// printf("command = %x\n",output->command);
	rip_start = rip_start + 4;
	for(int i = 0; i < enrty_num; ++ i){
		int family = (packet[rip_start ] << 8) + packet[rip_start + 1];
		int tag = (packet[rip_start + 2] << 8) + packet[rip_start + 3];
		if(tag != 0 || (command == 1  && family != 0) || (command == 2) && family !=2 ) return false; // 第三条判断
		uint32_t metric = (packet[rip_start + 16] << 24) + (packet[rip_start + 17] << 16) + (packet[rip_start + 18] << 8) + packet[rip_start + 19];
		uint32_t  mask = (packet[rip_start + 8] << 24) + (packet[rip_start + 9] << 16) + (packet[rip_start + 10] << 8) + packet[rip_start + 11];	
		if(metric < 1 || metric > 16) return false;  // 第四条判断
		uint32_t iterator = 0xa0000000;

		int judge = mask;
		// printf("%d", (judge & (judge >> 1)) == judge);
		if (!((judge & (judge >> 1)) == judge)) return false;  // 第五条判断
		// 保存
		RipEntry re ;
		uint32_t addr = (packet[rip_start + 4] << 24) + (packet[rip_start + 5] << 16) + (packet[rip_start + 6] << 8) + packet[rip_start + 7];
		//uint32_t nexthop = (packet[rip_start + 12] << 24) + (packet[rip_start + 13] << 16) + (packet[rip_start + 14] << 8) + packet[rip_start + 15];
		uint32_t nexthop = (packet[15] << 24) + (packet[14] << 16) + (packet[13] << 8) + packet[12];
		re.addr = htonl(addr);
		re.nexthop = nexthop;
		re.metric = htonl(metric);
		re.mask = htonl(mask);
		// printf("re.addr = %x , re.mask = %x , re.mrtric =  %x , re.nexthop = %x\n",re.addr,re.mask,re.metric,re.nexthop);
		output->entries[i] = re;
		// 地址变化
		rip_start += 20;
	}

	return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {  // buffer数组的每个元素是一个字节（8位）
	// TODO:
	int entry_num = rip->numEntries;
	// 第一步，RIP头部
	// uint8_t command = ntohl(rip->command) & 0xff;
	uint8_t command = rip->command;
	buffer[0] = command;
	buffer[1] = 0x2;
	buffer[2] = buffer[3] = 0x0;
	// 第二步，构造每个表项
	int iterator = 4;  //地址偏移量
	for(int i = 0; i < entry_num; ++ i){
		buffer[iterator] = 0x0;      // family_hi
		buffer[iterator + 1] = command == 1 ? 0x0 : 0x2;   // family_lo
		buffer[iterator + 2] = buffer[iterator + 3] = 0;  // tag
		uint32_t addr = ntohl(rip->entries[i].addr);   // ip address
		buffer[iterator + 4] = addr >> 24;
		buffer[iterator + 5] = (addr >> 16) & 0xff;
		buffer[iterator + 6] = (addr >> 8) & 0xff;
		buffer[iterator + 7] = addr & 0xff;
		uint32_t mask = ntohl(rip->entries[i].mask); // subnet mask
		buffer[iterator + 8] = mask >> 24;
		buffer[iterator + 9] = (mask >> 16) & 0xff;
		buffer[iterator + 10] = (mask >> 8) & 0xff;
		buffer[iterator + 11] = mask & 0xff;
		uint32_t nexthop = ntohl(rip->entries[i].nexthop); // next hop
		buffer[iterator + 12] = nexthop >> 24;
		buffer[iterator + 13] = (nexthop >> 16) & 0xff;
		buffer[iterator + 14] = (nexthop >> 8) & 0xff;
		buffer[iterator + 15] = nexthop & 0xff;
		uint32_t metrix = ntohl(rip->entries[i].metric); //metrix
		// printf("in assemble, metric is %x\n", metrix);
		buffer[iterator + 16] = metrix>> 24;
		buffer[iterator + 17] = (metrix >> 16) & 0xff;
		buffer[iterator + 18] = (metrix >> 8) & 0xff;
		buffer[iterator + 19] = metrix & 0xff;

		iterator += 20;
	}
	return 4 + 20 * rip->numEntries;
}
