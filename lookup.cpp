#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h> 
#include <stack>
#include<vector>
#include"router.h"

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
	uint32_t metric;
	int interface;
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

int enrty_num = 0;
bool sth_change = false;
std::vector<RoutingTableEntry> table;
uint32_t tem_addr;
int mask_len;

struct node{
	node* father; // 父节点
	node* lc;   // 左孩子
	node* rc;   // 右孩子
	bool has_pre; // 是否存在一个前缀长度到此为止的IP
	uint32_t if_index; // 小端序，出端口编号
	uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
	uint32_t metric;
	int inrerface;    // 从哪口收到的信息
	node(){
		father = nullptr;
		lc = nullptr;
		rc = nullptr;
		has_pre = false;
		metric = 0;
		if_index = 0;
		nexthop = 0;
		inrerface = -1;
	}
	~node(){}
};

node* root = new node();

void insert(uint32_t addr, int len, uint32_t if_index, uint32_t nexthop, int interface, uint32_t metric){
	node* nod = root;                    // 字典树当前访问的节点
	uint32_t iterator = 0x80000000;
	//printf("in insert\n");
	for(int i = 0; i < len; ++ i){
		bool flag = iterator & addr;
		//printf("%d",flag);  // 打印路径
		iterator = iterator >> 1;
		if(flag){     // 右转
			if(nod->rc == nullptr){
				nod->rc = new node();
				nod->rc->father = nod;
				nod = nod->rc;
			}
			else nod = nod->rc;
		}
		else{        // 左转
			if(nod->lc == nullptr){
				nod->lc = new node();
				nod->lc->father = nod;
				nod = nod->lc;
			}
			else nod = nod->lc;
		}
		if(i == len - 1){    // 到达了IP前缀的尾部
			if(!nod->has_pre){
				printf("interface is %d\n",interface);
				 nod->inrerface = interface;
				 enrty_num ++;
				//  printf("insert: in metric = %x",metric);
				nod->metric = metric + 1;
				nod->nexthop = nexthop;
				nod->if_index = if_index;
				nod->has_pre = true;
				sth_change = true;
			 }
		}
	}
}

void remove(uint32_t addr, int len, uint32_t if_index, uint32_t nexthop){
	node* nod = root;                    // 字典树当前访问的节点
	uint32_t iterator = 0x80000000;
	for(int i = 0; i < len; ++ i){
		bool flag = iterator & addr;
		// printf("%d",flag);  // 打印路径
		iterator = iterator >> 1;
		if(flag){     // 右转
			if(nod->rc == nullptr)
				return;
			else nod = nod->rc;
		}
		else{        // 左转
			if(nod->lc == nullptr)
				return;
			else nod = nod->lc;
		}
		if(i == len - 1){  // 删除
			node* father = nod->father;
			int height = len - 1;
			enrty_num --;
			while(father != nullptr){
				if(nod->lc != nullptr || nod->rc != nullptr){    // 节点仍存在孩子，不删除节点本身，且停止回溯
					nod->has_pre = false;
					nod->nexthop = 0;
					nod->if_index = 0;
					sth_change = true;
					break;
				}
				else if(nod->has_pre && ! (height == len - 1)){          // 节点存在别的前缀，且不是最初想要删除的节点，停止删除
					break;
				}
				else{
					if(nod == nod->father->lc){  // 待删除节点是父节点的左孩子
						nod = nod->father;
						father = nod->father;
						node* tem = nod->lc;
						nod->lc = nullptr;
						delete tem;
						height --;
					}
					else{  // 是右孩子
						nod = nod->father;
						father = nod->father;
						node* tem = nod->rc;
						nod->rc = nullptr;
						delete tem;
						height --;
					}
				}
			}
		}
	}
}

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool is_insert, RoutingTableEntry entry, int interface) {
  	// TODO:
	uint32_t re_addr = entry.addr;
	uint32_t addr = ntohl(re_addr);
	//printf("update\n");
	// printf("insert : %d.%d.%d.%d\n",(addr & 0xff000000) >> 24, (addr & 0x00ff0000) >> 16, (addr & 0x0000ff00) >> 8, addr & 0x000000ff);
	if(is_insert) insert(addr,entry.len, entry.if_index,entry.nexthop,interface, ntohl(entry.metric));
	else remove(addr,entry.len, entry.if_index,entry.nexthop);
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t ask_addr, uint32_t *nexthop, uint32_t *if_index) {
	// TODO:
	uint32_t re_addr = ask_addr;
	uint32_t addr = ntohl(re_addr);    // 大端变小端
	*nexthop = 0;
	*if_index = 0;
	
	node* nod = root;                    // 字典树当前访问的节点
	uint32_t iterator = 0x80000000;
	std::stack <node*> node_stack;
	for(int i = 0; i < 32; ++ i){		 // 尽量往下走，走不动的话访问最后到达的节点
		bool flag = iterator & addr;
		// printf("%d",flag);  // 打印路径
		iterator = iterator >> 1;
		if(flag){     // 右转
			if(nod->rc == nullptr){
				if(nod->has_pre){
					*nexthop = nod->nexthop;
					*if_index = nod->if_index;
					return true;
				}
				if(!node_stack.empty()){
					node* find = node_stack.top();
					*nexthop = find->nexthop;
					*if_index = find->if_index;
					return true;
				}
				return false;
			}
				
			nod = nod->rc;
			if(nod->has_pre) node_stack.push(nod);
		}
		else{        // 左转
			if(nod->lc == nullptr){
				if(nod->has_pre){
					*nexthop = nod->nexthop;
					*if_index = nod->if_index;
					return true;
				}
				if(!node_stack.empty()){
					node* find = node_stack.top();
					*nexthop = find->nexthop;
					*if_index = find->if_index;
					return true;
				}
				return false;
			}
			else nod = nod->lc;
			if(nod->has_pre) node_stack.push(nod);
		}
		if(i == 31){    // 顺利访问到了叶子
			*nexthop = nod->nexthop;
			*if_index = nod->if_index;
			return true;
		}
	}
  return false;
}

void visit(node* visitor, int interface){
	if(visitor->has_pre){
		printf("find a table: addr is %x, interface is %d, metric = %x\n",htonl(tem_addr),visitor->if_index,visitor->metric);
		// if(interface != -1 && visitor->inrerface == interface){
		// 	printf("conflict: %x, interface is %d", htonl(tem_addr),interface);
		// }
		// else{
		RoutingTableEntry en;
		en.addr = htonl(tem_addr << (32-mask_len));
		en.if_index = visitor->if_index;
		en.len = mask_len;
		en.nexthop = visitor->nexthop;
		en.metric = htonl(visitor->metric);
		en.interface = visitor->inrerface;
		table.push_back(en);
		uint32_t addr = tem_addr << (32-mask_len);
			// printf("find : %d.%d.%d.%d\n",(addr & 0xff000000) >> 24, (addr & 0x00ff0000) >> 16, (addr & 0x0000ff00) >> 8, addr & 0x000000ff);
		// }
	}
	if(visitor->lc != nullptr){
		mask_len ++;
		tem_addr = (tem_addr << 1) + 0;
		visit(visitor->lc, interface);
		mask_len --;
		tem_addr = tem_addr >> 1;
	}
	if(visitor->rc != nullptr){
		mask_len ++;
		tem_addr = (tem_addr << 1) + 1;
		visit(visitor->rc,interface);
		mask_len --;
		tem_addr = tem_addr >> 1;
	}
}

/**
 * @brief 获得所有路由表
 * @param sth_change 是否有表项发生变化，没有的话直接传送原table，不再遍历了
 * @param interface 读入表项的端口号，用于水平分裂
 * 
 */
std::vector<RoutingTableEntry> getTable(int interface){
	if(!sth_change) {
		sth_change = false;
		printf("after print, table's size =%d\n",table.size());
		return table;
	}
	table.clear();
	printf("after print, table's size =%d\n",table.size());
	mask_len = 0;
	tem_addr = 0;
	visit(root, interface);
	enrty_num = table.size();
	sth_change = false;
	printf("interface is %d, table size is %d\n addr : ", interface, table.size());
	for(int i = 0; i < table.size(); ++ i){
		printf("%x (%x) ,metric = %x ", table.at(i).addr, table.at(i).if_index, table.at(i).metric);
	}
	printf("\n");
	return table;
}
