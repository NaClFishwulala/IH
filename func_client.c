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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/aead.h>
#include <crypto/authenc.h>
#include <crypto/hash.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <crypto/aes.h>
#include "checksum.h"
#include "authclient.h"
#include "encrypt2.h"
#include "AES.h"



MODULE_LICENSE("GPL");
#define DRV_VERSION "0.1"
#define VNI_PROTO 0xf4f0
#define AUTH	0
#define AES	1
#define CHECKSUM	0
#define ENCRYPT_WORKMODE 0
#define ENCRYPT_MODE 0x00
#define ENCRYPT_ALG 0x00
#define CHECKSUM_WORKMODE 0
#define CHECKSUM_MODE 0x00
#define CHECKSUM_ALG 0x00

/*
 * The devices
 */


struct vni_priv_data{
	__u16 sequence;
	__u16 pkt_tx_num;
	__u16 pkt_tx_prenum;
	__u16 pkt_rx_num;
	__u16 pkt_rx_prenum;
	__u32 bytes_tx_num;
	__u32 bytes_tx_prenum;
	__u32 bytes_rx_num;
	__u32 bytes_rx_prenum;
	struct  timer_list  funTimer;
};

struct vni_priv {
	struct net_device_stats stats;
	int status;
	struct sk_buff* skb;
	__u16 sequence;
	__u16 pkt_tx_num;
	__u16 pkt_tx_prenum;
	__u16 pkt_rx_num;
	__u16 pkt_rx_prenum;
	__u32 bytes_tx_num;
	__u32 bytes_tx_prenum;
	__u32 bytes_rx_num;
	__u32 bytes_rx_prenum;
	spinlock_t lock;
};

struct  vnihdr//虚拟链路协议的头部
{
	unsigned char enc_mode;
	unsigned char enc_alg;
	unsigned char check_mode;
	unsigned char check_alg;
	unsigned short checksum;
	unsigned short type;
}__attribute__((packed));

struct net_device* vni_dev;
struct net_device_ops vni_dev_ops;
struct vni_priv_data vni_data;
struct ecb_aes_ctx aes_ecb_ctx;
struct ecb_des_ctx des_ecb_ctx;
unsigned char ecb_aes_key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
unsigned char ecb_des_key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

//该函数向内核协议栈发送控制信息，通知其开启指定网络设备的数据传输通道，从而开始协议栈向该网络设备发送数据报。
int vni_open(struct net_device* dev)
{
	unsigned char MAC[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x81, 0x56, 0xe9}; 
	memcpy(dev->dev_addr, MAC, ETH_ALEN);
	netif_start_queue(dev);//控制内核让协议栈向虚拟网络设备发送数据报
	return 0;
}

int vni_release(struct net_device* dev)
{
	netif_stop_queue(dev); /* can't transmit any more */
	return 0;
}

/*
 * Configuration changes (passed on by ifconfig)
 */
//ͨ��ifconfig���Դ�����Щ������
int vni_config(struct net_device* dev, struct ifmap* map)
{
	if (dev->flags & IFF_UP) /* can't act on a running interface */
		return -EBUSY;

	/* Don't allow changing the I/O address */
	if (map->base_addr != dev->base_addr) {
		printk(KERN_WARNING "vni: Can't change I/O address\n");
		return -EOPNOTSUPP;
	}

	/* Allow changing the IRQ */
	if (map->irq != dev->irq) {
		dev->irq = map->irq;
		/* request_irq() is delayed to open-time */
	}

	/* ignore other fields */
	return 0;
}

/*
 * Transmit a packet (called by the kernel)
 */
netdev_tx_t vni_tx(struct sk_buff* skb, struct net_device* dev)
{

	struct vni_priv* priv = netdev_priv(dev);
	struct ethhdr* eth;
	struct ethhdr pre_ethhdr;
	struct vnihdr* vni;
	unsigned char* p;
	unsigned short* checkbuf;
	unsigned char* checkbuf2;
//	unsigned char destaddr[ETH_ALEN] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
	struct sk_buff* skb2;
	struct net_device* ens_dev;

	ens_dev = dev_get_by_name(&init_net, "ens33");
	printk(KERN_INFO "tx: get one packet from kernal send to dev:%s\n", skb->dev->name);

	if (skb_headroom(skb) < (2 + sizeof(struct vnihdr))) {
		skb2 = skb_realloc_headroom(skb, (2 + sizeof(struct vnihdr)));
		if (!skb2) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		consume_skb(skb);
		skb = skb2;
	}

	eth = (struct ethhdr*)skb->data;
	memcpy(pre_ethhdr.h_source, eth->h_source, ETH_ALEN);
	memcpy(pre_ethhdr.h_dest, eth->h_dest, ETH_ALEN);
	pre_ethhdr.h_proto = eth->h_proto;
	skb_pull(skb,sizeof(struct ethhdr));

	p = skb_push(skb, sizeof(struct vnihdr));
	vni = (struct vnihdr*)p;
	vni->enc_mode = ENCRYPT_MODE;
	vni->enc_alg = ENCRYPT_ALG;
	vni->check_mode = CHECKSUM_MODE;
	vni->check_alg = CHECKSUM_ALG;
	vni->checksum = 0;
	vni->type = pre_ethhdr.h_proto;

	p = skb_push(skb, sizeof(struct ethhdr));
	skb_reset_mac_header(skb);
	eth = (struct ethhdr*)p;
	memcpy(eth->h_source, ens_dev->dev_addr, ETH_ALEN);
	memcpy(eth->h_dest, pre_ethhdr.h_dest, ETH_ALEN);
	eth->h_proto = htons(VNI_PROTO);
	//
	if (unlikely(CHECKSUM_WORKMODE == 1)) {
		if ((CHECKSUM_MODE == 0x02) && (CHECKSUM_ALG == 0x01)) {
			checkbuf = (unsigned short*)((unsigned char*)p + sizeof(struct ethhdr));
			vni->checksum = checksum1(checkbuf, sizeof(struct vnihdr));
		}
		else if ((CHECKSUM_MODE == 0x01) && (CHECKSUM_ALG == 0x01)) {
			checkbuf = (unsigned short*)p ;
			vni->checksum = checksum1(checkbuf, sizeof(struct vnihdr)+sizeof(struct ethhdr));
		}
		else if ((CHECKSUM_MODE == 0x03) && (CHECKSUM_ALG == 0x02)) {
			checkbuf2 = (unsigned char*)p;
			vni->checksum = checksum2(checkbuf2, ecb_aes_key, 6 + sizeof(struct vnihdr) + 16);
		}
		else if ((CHECKSUM_MODE == 0x00) && (CHECKSUM_ALG == 0x00)) {
			vni->checksum = 0;
		}
		else {
			printk(KERN_INFO "wrong CHECKSUM_MODE、CHECKSUM_ALG\n");
			return -1;
		}
	}
	if(unlikely(ENCRYPT_WORKMODE == 1)){
		if ((ENCRYPT_MODE == 0x01) && (ENCRYPT_ALG == 0x01)) {
			skb_pull(skb, sizeof(struct ethhdr));
			skb = ecb_aes_skb_encrypt(skb,ecb_aes_key,&aes_ecb_ctx);
			p = skb_push(skb, sizeof(struct ethhdr));
		}
		else if ((ENCRYPT_MODE == 0x01) && (ENCRYPT_ALG == 0x02)) {
			skb_pull(skb, sizeof(struct ethhdr));
			skb = ecb_des_skb_encrypt(skb,ecb_des_key,&des_ecb_ctx);
			p = skb_push(skb, sizeof(struct ethhdr));
		}
		else if ((ENCRYPT_MODE == 0x02) && (ENCRYPT_ALG == 0x01)) {
			skb_pull(skb, sizeof(struct ethhdr));
			skb_pull(skb, sizeof(struct vnihdr));
			skb = ecb_aes_skb_encrypt(skb, ecb_aes_key, &aes_ecb_ctx);
			skb_push(skb, sizeof(struct vnihdr));
			p = skb_push(skb, sizeof(struct ethhdr));
		}
		else if ((ENCRYPT_MODE == 0x02) && (ENCRYPT_ALG == 0x02)) {
			skb_pull(skb, sizeof(struct ethhdr));
			skb_pull(skb, sizeof(struct vnihdr));
			skb = ecb_des_skb_encrypt(skb, ecb_des_key, &des_ecb_ctx);
			skb_push(skb, sizeof(struct vnihdr));
			p = skb_push(skb, sizeof(struct ethhdr));
		}
		else {
			printk(KERN_INFO "wrong ENCRYPT_MODE、ENCRYPT_ALG\n");
			return -1;
		}
    }

	vni_data.pkt_tx_num++;
	dev->stats.tx_packets++;
	priv->skb = skb;
	skb->dev = ens_dev;
	dev_queue_xmit(skb);
	//printk(KERN_INFO "dev:%s send one packet, sequence:%d\n", skb->dev->name, priv->sequence);
	priv->sequence++;
	return NETDEV_TX_OK; /* Our simple device can not fail */
}


/*
 * Ioctl commands
 */
int vni_ioctl(struct net_device* dev, struct ifreq* rq, int cmd)
{
	//PDEBUG("ioctl\n");
	return 0;
}

/*
 * Return statistics to the caller
 */
struct net_device_stats* vni_stats(struct net_device* dev)
{
	struct vni_priv* priv = netdev_priv(dev);
	return &priv->stats;
}

/*
 * The "change_mtu" method is usually not needed.
 * If you need it, it must be like this.
 */
int vni_change_mtu(struct net_device* dev, int new_mtu)
{
	unsigned long flags;
	struct vni_priv* priv = netdev_priv(dev);
	spinlock_t* lock = &priv->lock;

	/* check ranges */
	if ((new_mtu < 68) || (new_mtu > 1500))
		return -EINVAL;
	/*
	 * Do anything you need, and the accept the value
	 */
	spin_lock_irqsave(lock, flags);
	dev->mtu = new_mtu;
	spin_unlock_irqrestore(lock, flags);
	return 0; /* success */
}

/*
 * This function is called to fill up an eth header, if arp is not
 * available on the interface
 */
int vni_rebuild_header(struct sk_buff* skb, struct net_device* dev)
{
	//struct vni_priv* priv = netdev_priv(dev);
	struct ethhdr* eth = (struct ethhdr*)skb->data;
	//struct vnihdr* vni = (struct vnihdr*)((unsigned char*)skb->data + sizeof(struct ethhdr));
	unsigned char destaddr[ETH_ALEN] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
	struct net_device* ens_dev;

	ens_dev = dev_get_by_name(&init_net, "ens33");

	memcpy(eth->h_source, ens_dev->dev_addr, ens_dev->addr_len);
	memcpy(eth->h_dest, destaddr, ETH_ALEN);
	//eth->h_proto = htons(VNI_PROTO);
	//vni->number1 = 5;
	//vni->number2 = 0;
	//vni->number3 = 2;
	//vni->number4 = 3;
	//vni->sequence = htons(priv->sequence);
	return 0;
}

int vni_header(struct sk_buff* skb, struct net_device* dev,
	unsigned short type, void* daddr, void* saddr,
	unsigned int len)
{
	struct ethhdr* eth = (struct ethhdr*)skb_push(skb, ETH_HLEN);
	unsigned char destaddr[ETH_ALEN] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
	struct net_device* ens_dev;
	ens_dev = dev_get_by_name(&init_net, "ens33");

	eth->h_proto = htons(type);
	memcpy(eth->h_source, ens_dev->dev_addr, ens_dev->addr_len);
	memcpy(eth->h_dest, destaddr, ETH_ALEN);

	return (dev->hard_header_len);
}

/*
 * Deal with a transmit timeout.
 */
void vni_tx_timeout(struct net_device* dev)
{
	struct vni_priv* priv = netdev_priv(dev);

	/* Simulate a transmission interrupt to get things moving */
	//priv->status = SNULL_TX_INTR;
	//vni_interrupt(0, dev, NULL);
	printk(KERN_INFO "vni_tx_timeout\n");
	priv->stats.tx_errors++;
	netif_wake_queue(dev);
	return;
}



int vni_rx(struct sk_buff* skb, struct net_device* dev,
	struct packet_type* ptype, struct net_device* orig_dev)
{
	//struct vni_priv* priv = netdev_priv(dev);
	struct sk_buff* sb = skb;
	struct ethhdr* eth;
	struct vnihdr* vni;
	struct net_device* vni_dev;
	unsigned char* p;
	unsigned short check_result;
	unsigned short* checkbuf;
	unsigned char* checkbuf2;
	unsigned char auth_result = 0;
	struct net_device* ens_dev;
	unsigned char MAC[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x81, 0x56, 0xe9};

	ens_dev = dev_get_by_name(&init_net, "ens33");
	vni_dev = dev_get_by_name(&init_net,"vni0");
	printk(KERN_INFO "rx:get one packet from dev:%s\n", skb->dev->name);
	if(strcmp(skb->dev->name, "ens33") != 0){
		printk(KERN_INFO "rec drop!\n");
		kfree_skb(skb);
		return NET_RX_DROP;
	}/*
	if(strcmp(skb->dev->name, "ens33") == 0){
		printk(KERN_INFO "rec drop!\n");
		kfree_skb(skb);
		return NET_RX_DROP;
	}*/
	eth = eth_hdr(sb);
	//printk(KERN_INFO "SRC MAC: %pM\n", &eth->h_source);
	//printk(KERN_INFO "DST MAC: %pM\n", &eth->h_dest);
	//printk(KERN_INFO "MAC protocol: 0x%04x\n", ntohs(eth->h_proto));
	p = (unsigned char*)eth + sizeof(struct ethhdr);
	vni = (struct vnihdr*)p;
	if (unlikely(AUTH == 1)) {
		auth_result = authentication_client( p, eth->h_source, MAC, ens_dev);
		if (auth_result != 1) {
			return 0;
		}
	}
    if(unlikely(ENCRYPT_WORKMODE == 1)){
		if ((ENCRYPT_MODE == 0x01) && (ENCRYPT_ALG == 0x01)) {
			sb = ecb_aes_skb_decrypt(sb,ecb_aes_key,&aes_ecb_ctx);
			eth = eth_hdr(sb);
			p = (unsigned char*)eth + sizeof(struct ethhdr);
			vni = (struct vnihdr*)p;
		}
		else if ((ENCRYPT_MODE == 0x01) && (ENCRYPT_ALG == 0x02)) {
			sb = ecb_des_skb_decrypt(sb,ecb_des_key,&des_ecb_ctx);
			eth = eth_hdr(sb);
			p = (unsigned char*)eth + sizeof(struct ethhdr);
			vni = (struct vnihdr*)p;
		}
		else if ((ENCRYPT_MODE == 0x02) && (ENCRYPT_ALG == 0x01)) {
			skb_pull(skb, sizeof(struct vnihdr));
			sb = ecb_aes_skb_decrypt(sb, ecb_aes_key, &aes_ecb_ctx);
			skb_push(skb, sizeof(struct vnihdr));
			eth = eth_hdr(sb);
			p = (unsigned char*)eth + sizeof(struct ethhdr);
			vni = (struct vnihdr*)p;
		}
		else if ((ENCRYPT_MODE == 0x02) && (ENCRYPT_ALG == 0x02)) {
			skb_pull(skb, sizeof(struct vnihdr));
			sb = ecb_des_skb_decrypt(sb, ecb_des_key, &des_ecb_ctx);
			skb_push(skb, sizeof(struct vnihdr));
			eth = eth_hdr(sb);
			p = (unsigned char*)eth + sizeof(struct ethhdr);
			vni = (struct vnihdr*)p;
		}
		else {
			printk(KERN_INFO "wrong ENCRYPT_MODE、ENCRYPT_ALG\n");
			return -1;
		}
	    //printk(KERN_INFO "DEBUG:ID:%d%d%d%d\n",vni->number1,vni->number2,vni->number3,vni->number4);
    }
	if (unlikely(CHECKSUM_WORKMODE == 1)) {
		if ((CHECKSUM_MODE == 0x02) && (CHECKSUM_ALG == 0x01)) {
			checkbuf = (unsigned short*)p;
			check_result = checksum1(checkbuf, sizeof(struct vnihdr));
			if (check_result != 0) {
				printk(KERN_INFO "check_result != 0\n");
				return -1;
			}
		}
		else if ((CHECKSUM_MODE == 0x01) && (CHECKSUM_ALG == 0x01)) {
			checkbuf = (unsigned short*)((unsigned char*)p - sizeof(struct ethhdr));
			check_result = checksum1(checkbuf, sizeof(struct ethhdr) + sizeof(struct vnihdr));
			if (check_result != 0) {
				printk(KERN_INFO "check_result != 0\n");
				return -1;
			}
		}
		else if ((CHECKSUM_MODE == 0x03) && (CHECKSUM_ALG == 0x02)) {
			checkbuf2 = (unsigned char*)((unsigned char*)p - sizeof(struct ethhdr));
			check_result = checksum2(checkbuf2, ecb_aes_key, 6 + sizeof(struct vnihdr) + 16);
			if (check_result != vni->checksum) {
				printk(KERN_INFO "check_result != vni->checksum\n");
				return -1;
			}
		}
		else {
			printk(KERN_INFO "wrong CHECKSUM_MODE、CHECKSUM_ALG\n");
			return -1;
		}
	}
	printk(KERN_INFO "ACE OK!\n");
	//printk(KERN_INFO "dev:%s recv one packet, ID: %d%d%d%d, sequence:%d, type:0x%04X\n", skb->dev->name, vni->number1, vni->number2, vni->number3, vni->number4, ntohs(vni->sequence), ntohs(vni->type));
	sb->protocol = vni->type;
	p = skb_pull(sb, sizeof(struct vnihdr));
	skb_reset_network_header(sb);
	vni_data.pkt_rx_num++;
	vni_dev->stats.rx_packets++;
	sb->dev = vni_dev;
	netif_rx(sb);
	return 0;
}

static struct packet_type vni_packet_type __read_mostly = {
.type = cpu_to_be16(VNI_PROTO),
.func = vni_rx,
};

//static void timer_function(struct timer_list  *timer)
//{
//	struct vni_priv* priv = netdev_priv(dev);
//	printk(KERN_INFO "send:packet_tx_total=%dpackets,pps=%d/1000 p/s\n", priv->pkt_tx_num, (priv->pkt_tx_num - priv->pkt_tx_prenum) * 1000 / 60);
//	printk(KERN_INFO "recv:packet_rx_total=%dpackets,pps=%d/1000 p/s\n", priv->pkt_rx_num, (priv->pkt_rx_num - priv->pkt_rx_prenum) * 1000 / 60);
//	priv->pkt_tx_prenum = priv->pkt_tx_num;
//	priv->pkt_rx_prenum = priv->pkt_rx_num;
//	mod_timer(&funTimer, jiffies + 60 * HZ);
//}

static void timer_function(struct timer_list  *timer)
{

	struct vni_priv_data* data = from_timer(data, timer, funTimer);
	printk(KERN_INFO "send:packet_tx_total=%dpackets,pps=%d/1000 p/s\n", data->pkt_tx_num, (data->pkt_tx_num - data->pkt_tx_prenum) * 1000 / 60);
	printk(KERN_INFO "recv:packet_rx_total=%dpackets,pps=%d/1000 p/s\n", data->pkt_rx_num, (data->pkt_rx_num - data->pkt_rx_prenum) * 1000 / 60);
	data->pkt_tx_prenum = data->pkt_tx_num;
	data->pkt_rx_prenum = data->pkt_rx_num;
	mod_timer(&data->funTimer, jiffies + 60 * HZ);
}

/*
 * The init function (sometimes called probe).
 * It is invoked by register_netdev()
 */
void vni_init(struct net_device* dev)
{
	struct vni_priv* priv;
	ether_setup(dev); 

	vni_dev_ops.ndo_open = vni_open;
	vni_dev_ops.ndo_stop = vni_release;
	vni_dev_ops.ndo_set_config = vni_config;
	vni_dev_ops.ndo_start_xmit = vni_tx;
	vni_dev_ops.ndo_get_stats = vni_stats;
	vni_dev_ops.ndo_do_ioctl = vni_ioctl;
	vni_dev_ops.ndo_change_mtu = vni_change_mtu;
	dev->netdev_ops = &vni_dev_ops;

//	dev->flags |= IFF_NOARP;//关闭了ARP

	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct vni_priv));
	spin_lock_init(&priv->lock);
	dev_add_pack(&vni_packet_type);
	printk(KERN_INFO "vni input packet module loaded\n");
	vni_data.funTimer.expires = jiffies + 60 * HZ;
	timer_setup(&vni_data.funTimer, timer_function, 0);
	add_timer(&vni_data.funTimer);
	printk(KERN_INFO "1min timer loaded\n");

//	dev->watchdog_timer.expires = jiffies + 60 * HZ;
//	timer_setup(&dev->watchdog_timer, test_timer_function, 0);
//	add_timer(&dev->watchdog_timer);
//	printk(KERN_INFO "test 1min timer loaded\n");

}

/*
 * Finally, the module stuff
 */
void vni_cleanup(void)
{
	unregister_netdev(vni_dev);
	free_netdev(vni_dev);
	dev_remove_pack(&vni_packet_type);
	if (ENCRYPT_WORKMODE == 1) {
		if (ENCRYPT_ALG == 0x01) {
			ecb_aes_cleanup(&aes_ecb_ctx);
		}
		else if (ENCRYPT_ALG == 0x02) {
			ecb_des_cleanup(&des_ecb_ctx);
		}
		else {
			printk(KERN_INFO "No legal ENCRYPT_ALG:%d\n", ENCRYPT_ALG);
		}
	}
	printk(KERN_INFO "vni input packet module removed\n");
	//del_timer(&funTimer);
	//printk(KERN_INFO "exit 1min timer\n");
	del_timer(&vni_data.funTimer);
	printk(KERN_INFO "exit test 1min timer\n");
	return;
}


int vni_init_module(void)
{
	int ret = -ENOMEM;
	int result;
	unsigned char MAC[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x81, 0x56, 0xe9};
	struct net_device* ens_dev;

	ens_dev = dev_get_by_name(&init_net, "ens33");
	vni_dev = alloc_netdev(sizeof(struct vni_priv), "vni%d", NET_NAME_ENUM, vni_init);
	if (vni_dev == NULL)
		goto out;
	ret = -ENODEV;

	if ((result = register_netdev(vni_dev)))
		printk(KERN_INFO "vni: error %i registering device \"%s\"\n", result, vni_dev->name);
	else
		ret = 0;

	if (ENCRYPT_WORKMODE == 1){
		if (ENCRYPT_ALG == 0x01) {
			ecb_aes_init(&aes_ecb_ctx);
		}
		else if (ENCRYPT_ALG == 0x02) {
			ecb_des_init(&des_ecb_ctx);
		}
		else {
			printk(KERN_INFO "No legal ENCRYPT_ALG:%d\n", ENCRYPT_ALG);
		}
    }

	if (AUTH == 1) {
		send_hello(MAC, ens_dev);
	}

out:
	if (ret)
		vni_cleanup();
	return ret;
}

module_init(vni_init_module);
module_exit(vni_cleanup);
MODULE_AUTHOR("Tzc");
