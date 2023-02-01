
#include <linux/time.h> 
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/rtnetlink.h>
#include <net/netns/generic.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <linux/ip.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <net/sock.h>
#include <linux/netfilter.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/kernel.h> 
#include <linux/slab.h> 
#include <linux/errno.h>  
#include <linux/types.h>  
#include <linux/interrupt.h> 
#include <linux/in.h>
#include <linux/in6.h>
#include <asm/checksum.h>

#define VNI_PROTO 0xf4f0

struct vniuser {
	const unsigned char* name;
	const unsigned char* password;
	unsigned char chap;
	unsigned short sequence;
};
struct vniuser user1 = { "test", "123456", 0, 0 };
unsigned char client_state = 0;

int send_hello(unsigned char* SrcMAC, struct net_device* dev)
{
	struct sk_buff* skb;
	unsigned short usernameLength;
	unsigned char* temp;
	unsigned char BROARCAST_MAC[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	usernameLength = strlen(user1.name);
	skb = alloc_skb(3 + usernameLength + 14 + 15, GFP_ATOMIC);
	if (skb == NULL) return -1;
	skb_reserve(skb, (14 + 15) & ~15);
	temp = (unsigned char*)skb_put(skb, 3 + usernameLength);
	*(unsigned char*)temp = 1;
	temp = temp + 1;
	*(unsigned short*)temp = htons(usernameLength);
	temp = temp + 2;
	memcpy(temp, user1.name, usernameLength);
	temp = (unsigned char*)skb_push(skb, 14);
	memcpy(temp, BROARCAST_MAC, 6);
	memcpy(temp + 6, SrcMAC, 6);//��Ҫ��Ϊ�Լ���MAC��ַ
	*(unsigned short*)(temp + 12) = htons(VNI_PROTO);
	skb->dev = dev;
	skb->protocol = __constant_htons(VNI_PROTO);//��Ҫ�޸�
	dev_queue_xmit(skb);
	client_state = 1;
	return 0;
}

int client_state1_fsm(unsigned char* data, unsigned char* SrcMAC, unsigned char* DstMAC, struct net_device* dev)
{
	unsigned char* temp;
	unsigned short sequence;
	unsigned short usernameLength;
	unsigned char response;
	unsigned char i;
	struct sk_buff* skb;

	switch (*(unsigned char*)data)
	{
	case 2:
		temp = data + 1;
		sequence = ntohs(*(unsigned short*)temp);
		temp = temp + 2;
		usernameLength = ntohs(*(unsigned short*)temp);
		temp = temp + 2;
		if (strncmp(temp, user1.name, usernameLength) == 0) {
			temp = temp + usernameLength;
			response = *(unsigned char*)temp;
			for (i = 0; i < strlen(user1.password); i++) {
				response = response ^ user1.password[i];
			}
			skb = alloc_skb(6 + usernameLength + 14 + 15, GFP_ATOMIC);
			if (skb == NULL) return -1;
			skb_reserve(skb, (14 + 15) & ~15);
			temp = (unsigned char*)skb_put(skb, 6 + usernameLength);
			*(unsigned char*)temp = 3;
			temp = temp + 1;
			*(unsigned short*)temp = htons(sequence);
			temp = temp + 2;
			*(unsigned short*)temp = htons(usernameLength);
			temp = temp + 2;
			memcpy(temp, user1.name, usernameLength);
			temp = temp + usernameLength;
			*(unsigned char*)temp = response;

			temp = (unsigned char*)skb_push(skb, 14);
			memcpy(temp, SrcMAC, 6);
			memcpy(temp + 6, DstMAC, 6);
			*(unsigned short*)(temp + 12) = htons(VNI_PROTO);

			skb->dev = dev;
			skb->protocol = __constant_htons(VNI_PROTO);//��Ҫ�޸�
			dev_queue_xmit(skb);
			client_state = 2;
			return 0;
		}
		break;
	default:
		return 2;
		break;
	}
	return 2;
}

int client_state2_fsm(unsigned char* data, unsigned char* SrcMAC, unsigned char* DstMAC, struct net_device* dev)
{
	unsigned char* temp;
	switch (*(unsigned char*)data)
	{
	case 4:
		temp = data + 1;
		if (*(unsigned char*)temp == 1) {
			client_state = 3;
			return 0;
		}
		else if (*(unsigned char*)temp == 2) {
			client_state = 0;
			return 0;
		}
		else {
			return 2;
		}
		break;
	default:
		return 2;
		break;
	}
	return 2;
}

int authentication_client (unsigned char* data, unsigned char* SrcMAC, unsigned char* DstMAC, struct net_device* dev)
{
	switch (client_state)
	{
	case 1:
		return client_state1_fsm(data, SrcMAC, DstMAC, dev);
		break;
	case 2:
		return client_state2_fsm(data, SrcMAC, DstMAC, dev);
		break;
	case 3:
		return 1;//��֤�ɹ������Ͻ�
		break;
	default:
		return 2;
		break;
	}
	return 2;
}




