#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <arpa/inet.h> 

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry, int interface);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern std::vector<RoutingTableEntry> getTable(int interface);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

uint8_t packet[2048];
uint8_t output[2048];

uint32_t * gnexthop = new uint32_t[1];
uint32_t * gif_index = new uint32_t[1];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 直连路由：你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};
macaddr_t bro_mac = {0x01,0x00,0x5e,0x00,0x00,0x09};

RipPacket** table(bool is_request, int interface, int* packet_num){
	RipPacket** re = new RipPacket*[210];
	if(is_request){
		*packet_num = 1;
		re[0] = new RipPacket();
		re[0]->numEntries = 1;
		re[0]->command = 0x01;
		RipEntry entry;
		entry.addr = 0x00000000;
		entry.nexthop = 0x00000000;
		entry.metric = 0x10000000;
		entry.mask = 0x00000000;
		re[0]->entries[0] = entry;
		return re;
	}
	//update_entrys
	std::vector<RoutingTableEntry> ta = getTable(interface);
	std::vector<RoutingTableEntry>::iterator it;
	int n = 0;
	for(it = ta.begin(); it != ta.end(); it ++){
		if(n % 25 == 0){
			*packet_num  = *packet_num + 1;

			re[*packet_num - 1] = new RipPacket(); 
			re[*packet_num - 1] ->numEntries = ta.size() - n >= 25 ? 25 : ta.size() - n;
			re[*packet_num - 1] ->command = 0x02;
		}
		RipEntry entry;
		entry.addr = it->addr;
		entry.nexthop = it->nexthop;
		entry.metric = interface == it->interface ? 0x10000000 :  it->metric;
		uint32_t mask = 0;
		for(int i = 0; i < it->len; ++ i){
			mask = (mask << 1) + 1;
		}
		for(int i = it->len; i < 32; ++ i){
			mask = (mask << 1);
		}
		entry.mask = htonl(mask);
		re[*packet_num - 1] ->entries[n % 25] = entry;
		n ++;
	}

	return re;
}

void print(){
	std::vector<RoutingTableEntry> ta = getTable(-1);
	std::vector<RoutingTableEntry>::iterator it;
	int n = 0;
	printf("路由表信息如下: \n");
	if(ta.size() > 100) {
		printf("路由表的大小为%d\n",ta.size());
		return;
	}
	for(it = ta.begin(); it != ta.end(); it ++){
			uint32_t addr  = ntohl(it->addr);
			printf("%d.%d.%d.%d",(addr & 0xff000000) >> 24, (addr & 0x00ff0000) >> 16, (addr & 0x0000ff00) >> 8, addr & 0x000000ff);
			int mask = it->len;
			*gnexthop = it->nexthop;
			*gif_index = it->if_index;
			// printf("\n");
			// uint32_t ite1 = 0x80000000;
			// while(ite1!=0){
			// 	printf("%d",(ite1&mask) != 0);
			// 	ite1 = ite1 >> 1;
			// }
			// printf("\n");

			// int mask_num = 32;
			// uint32_t ite = mask;
			// while(!(ite & 1) && mask_num > 0 ){
			// 	mask_num --;
			// 	ite = ite >> 1;
			// }
			printf("/%d",mask);

			if(*gnexthop == 0){                    // 直连路由
				uint32_t  nh = *gnexthop;
				printf(" dev %d scope link\n", *gif_index);
			}
			else{
				uint32_t nh = ntohl(*gnexthop);
				printf(" via %d.%d.%d.%d",(nh & 0xff000000) >> 24, (nh & 0x00ff0000) >> 16, (nh & 0x0000ff00) >> 8, nh & 0x000000ff);
				printf(" dev %d\n", *gif_index);
			}
    	}
}

void send_message(int interface, bool is_request){
	int packet_num = 0;
    RipPacket** packets =  table(is_request,interface, &packet_num);
	for(int i = 0; i < packet_num; ++ i){
		int num = assemble(packets[i], output + 28);   // 获得需要发送的rip内容，前28位填入ip和udp
		//if(is_request &&  num != 24) printf("_______________wrong in line 90!______________\n");
		// V=4，IHL=5，TOS(DSCP/ECN)=0，ID=0，FLAGS/OFF=0，TTL=1, Type=0x11
		output[0] = 0x45;
		output[1] = 0x00;
		int length = num + 28;
		output[2] = (length & 0xff00) >> 8;
		output[3] = length & 0xff;
		output[4] = output[5] = output[6] = output[7] = 0x0;
		output[8] = 0x01;
		output[9] = 0x11;
		// temp checksum = 0
		output[10] = output[11] = 0x0;
		// src addr
		uint32_t addr = htonl(addrs[interface]);   // 接口对应ip
		output[12] = (addr & 0xff000000) >> 24;
		output[13] = (addr & 0x00ff0000) >> 16;
		output[14] = (addr & 0x0000ff00) >> 8;
		output[15] = addr & 0x000000ff;
		// dec: 0xe0000009
		output[16] = 0xe0;
		output[17] = output[18] = 0x0;
		output[19] = 0x09;
		// 校验和
		uint32_t checksum = 0;   // 即将计算出的校验和
		for(int i = 0; i < 20; i += 2)  // 计算IP头每16位的和
			checksum += ((output[i] << 8) + output[i + 1]);
		while (checksum & 0xffff0000) // 确保和的高16位是0
			checksum = (checksum & 0xffff) + (checksum  >> 16);
		checksum = ~checksum;
		output[10] = (checksum & 0xff00) >> 8;
		output[11] = checksum & 0xff;
		// UDP
		output[20] = 0x02;
		output[21] = 0x08;
		output[22] = 0x02;
		output[23] = 0x08;
		int udp_length = length - 20;
		output[24] = (udp_length & 0xff00) >> 8;
		output[25] = udp_length & 0xff;
		output[26] = output[27]  = 0x00;

		// send
		HAL_SendIPPacket(interface,output,length,bro_mac);
	}
}



int main(int argc, char *argv[]) {
	// 0a. 初始化 HAL，打开调试信息
	int res = HAL_Init(1, addrs);
  	if (res < 0) {
		return res;
  	}

    // 0b. 创建若干条 /24 直连路由
	// Add direct routes
	// For example:
	// 10.0.0.0/24 if 0
	// 10.0.1.0/24 if 1
	// 10.0.2.0/24 if 2
	// 10.0.3.0/24 if 3
  	for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
		RoutingTableEntry entry = {
			.addr = addrs[i], // big endian
			.len = 24, // small endian
			.if_index = i, // small endian
			.nexthop = 0 ,// big endian, means direct
		    .metric = 0x00000000  //big endian
		};
		// printf("____!!__");
		update(true, entry, -1);
		// printf("____!!______");
  	}
	 print();
	  

	uint64_t last_time = 0;
	// 发送request请求
	send_message(0,true);
	send_message(1,true);
	
	while (1) {
		// 获取当前时间，处理定时任务
		uint64_t time = HAL_GetTicks();
		if (time > last_time + 5 * 1000) {   // 每5秒
			// 每5秒发一个response，RIPv2的组播地址是224.0.0.9
			printf("Timer\n");
			print();
			send_message(0,false);
			send_message(1,false);
			send_message(2,false);
			send_message(3,false);
			last_time = time;
		}

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                                  dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
	src_addr = (packet[15] << 24) + (packet[14] << 16) + (packet[13] << 8) + packet[12];
	dst_addr = (packet[19] << 24) + (packet[18] << 16) + (packet[17] << 8) + packet[16];

	printf("catch a packet from %d :src is %x, and dst is %x\n", if_index, src_addr, dst_addr);

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    
    if (dst_is_me || dst_addr == 0x090000e0) {
		printf("handle packet\n");
    	RipPacket rip;
      	if (disassemble(packet, res, &rip)) {
        	if (rip.command == 1) {
          	// request
          	RipPacket** resp;
          	// TODO: fill resp
			int packet_num = 1;
			resp = table(false, if_index, &packet_num);
			for(int i = 0; i < packet_num; ++ i){
				// assemble
				// RIP
				uint32_t rip_len = assemble(resp[i], &output[20 + 8]);
				// IP
				output[0] = 0x45;
				output[1] = 0x00;
				int length = rip_len + 28;
				output[2] = (length & 0xff00) >> 8;
				output[3] = length & 0xff;
				output[4] = output[5] = output[6] = output[7] = 0x0;
				output[8] = 0x01;
				output[9] = 0x11;
				// temp checksum = 0
				output[10] = output[11] = 0x0;
				// src addr
				uint32_t addr = htonl(addrs[if_index]);   // 接口对应ip
				output[12] = (addr & 0xff000000) >> 24;
				output[13] = (addr & 0x00ff0000) >> 16;
				output[14] = (addr & 0x0000ff00) >> 8;
				output[15] = addr & 0x000000ff;
				// dec: src_addr
				output[16] = src_addr & 0xff;
				output[17] = (src_addr & 0xff00) >> 8;
				output[18] = (src_addr & 0xff0000) >> 16;
				output[19] = (src_addr & 0xff000000) >> 24;
				// 校验和
				uint32_t checksum = 0;   // 即将计算出的校验和
				for(int i = 0; i < 20; i += 2)  // 计算IP头每16位的和
					checksum += ((output[i] << 8) + output[i + 1]);
				while (checksum & 0xffff0000) // 确保和的高16位是0
					checksum = (checksum & 0xffff) + (checksum  >> 16);
				checksum = ~checksum;
				output[10] = (checksum & 0xff00) >> 8;
				output[11] = checksum & 0xff;
				// UDP
				output[20] = 0x02;
				output[21] = 0x08;
				output[22] = 0x02;
				output[23] = 0x08;
				int udp_length = length - 20;
				output[24] = (udp_length & 0xff00) >> 8;
				output[25] = udp_length & 0xff;
				output[26] = output[27]  = 0x00;
					
				// checksum calculation for ip and udp
				// if you don't want to calculate udp checksum, set it to zero
				// send it back
				HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
			}
        } else {
          // response
          // TODO: use query and update
	  			printf("rip's entries num = %d\n",rip.numEntries);
				for(int i = 0; i < rip.numEntries; ++ i){
					// int len = 0; bug!
					int len = 32;
					printf("packet[%d] : addr is %x\n", i, rip.entries[i].addr);
					uint32_t ite = ntohl(rip.entries[i].mask);
					while(!(ite & 1) && len > 0 ){
						len --;
						ite = ite >> 1;
				}
				// printf("next hop is %x, if_index = %d, metric = %x\n", rip.entries[i].nexthop, if_index,rip.entries[i].metric);
				if(rip.entries[i].metric == 0x10000000) continue;  //对metric为16的包直接丢弃
				RoutingTableEntry entry = {
					.addr = rip.entries[i].addr, // big endian
					.len =  len,// small endian
					.if_index = if_index, // small endian
					.nexthop = rip.entries[i].nexthop, // big endian, 0 means direct
					.metric = rip.entries[i].metric  //big endian
				};
		// printf("____!!__");
				update(true, entry, if_index);
			}
        }
      }
    } else {
      fprintf(stderr,"dst isn't me\n");
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      uint32_t nexthop1, dest_if;
      if (query(dst_addr, &nexthop1, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop1 == 0) {
          nexthop1 = dst_addr;
        }
	printf("nexthop:%x,dest_if:%d",nexthop1,dest_if);
        if (HAL_ArpGetMacAddress(dest_if, nexthop1, dest_mac) == 0) {
          memcpy(output, packet, res); // found
          if(forward(output, res)){
            fprintf(stderr,"forwarding checksum updated\n");
          }else{
            fprintf(stderr,"forwarding checksum failed\n");
          } // update ttl and checksum
            fprintf(stderr,"forwarding to %x through if%d\n",nexthop1,dest_if);
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
        //   }
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop1);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}
