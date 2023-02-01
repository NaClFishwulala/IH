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
#include <crypto/skcipher.h>

#define SG_MAX 20
#define VNI_PROTO 0xf4f0

struct ecb_aes_ctx {
	struct crypto_skcipher* tfm;
	struct skcipher_request* req;
	struct completion complete;
	int err;
};

static void ecb_aes_cb(struct crypto_async_request* req, int error) {
	struct ecb_aes_ctx* ctx = req->data;//?ecb_aes_ctx
	if (error == -EINPROGRESS) return;
	ctx->err = error;
	complete(&ctx->complete);
}

static void ecb_aes_init(struct ecb_aes_ctx* ctx) {
	ctx->tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
	ctx->req = skcipher_request_alloc(ctx->tfm, GFP_KERNEL);
	skcipher_request_set_callback(ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG, ecb_aes_cb, ctx);
	init_completion(&ctx->complete);
}

static void ecb_aes_cleanup(struct ecb_aes_ctx* ctx) {
	skcipher_request_free(ctx->req);
	crypto_free_skcipher(ctx->tfm);
}

int ecb_aes_encrypt(void* key, struct scatterlist* sg, unsigned int size, struct ecb_aes_ctx* ctx) {
	int ret;
	crypto_skcipher_setkey(ctx->tfm, key, 16);
	skcipher_request_set_crypt(ctx->req, sg, sg, size, NULL);
	ret = crypto_skcipher_encrypt(ctx->req);
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion(&ctx->complete);
		ret = ctx->err;
	}
	return ret;
}

int ecb_aes_decrypt(void* key, struct scatterlist* sg, unsigned int size, struct ecb_aes_ctx* ctx) {
	int ret;
	crypto_skcipher_setkey(ctx->tfm, key, 16);
	skcipher_request_set_crypt(ctx->req, sg, sg, size, NULL);
	ret = crypto_skcipher_decrypt(ctx->req);
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion(&ctx->complete);
		ret = ctx->err;
	}
	return ret;
}


struct sk_buff* ecb_aes_skb_encrypt(struct sk_buff* skb, unsigned char* KEY, struct ecb_aes_ctx* ctx) {
        struct sk_buff* trailer;
        struct scatterlist sg[SG_MAX];
	unsigned char err;
        unsigned char* tail;
        unsigned char blksize;
        unsigned int clen;
        unsigned char nfrags;
        unsigned char i;
        unsigned char* key = KEY;
        if (skb == NULL) return NULL;
        clen = skb->len;
	if (clen < 46){
		clen = 46;
	}
        blksize = ALIGN(16, 4);
        clen = ALIGN(clen + 1, blksize);
        nfrags = skb_cow_data(skb, clen - skb->len, &trailer);
        if(nfrags < 0){
                printk(KERN_INFO "nfrags < 0\n");
                return NULL;
        }
	if(trailer == NULL){
                printk(KERN_INFO "trailer == NULL\n");
                return NULL;
        }
        tail = skb_tail_pointer(trailer);
        for (i = 0; i < clen - skb->len - 1; i++)
                *(unsigned char*)(tail + i) = i + 1;
	*(unsigned char*)(tail + clen - skb->len - 1) = (clen - skb->len) - 1;
        pskb_put(skb, trailer, clen - skb->len);
        skb_to_sgvec(skb, sg, 0, clen);
        err = ecb_aes_encrypt(key, sg, clen, ctx);
	if(err < 0){
		printk(KERN_INFO "encrypt:err<0\n");
		return NULL;
	}
        return skb;
}

struct sk_buff* ecb_aes_skb_decrypt(struct sk_buff* skb, unsigned char* KEY, struct ecb_aes_ctx* ctx) {
        struct sk_buff* trailer;
        struct scatterlist sg[SG_MAX];
        unsigned char blksize;
        unsigned char err;
	unsigned int elen;
	unsigned char padlen;
        unsigned char nfrags;
	unsigned char* p;
	struct ethhdr* eth;
        unsigned char* key = KEY;
        if (skb == NULL) return NULL;
        elen = skb->len;
        blksize = ALIGN(16, 4);
	if(elen <= 0){
		printk(KERN_INFO "elen <= 0\n");
		return NULL;
	}
	if(elen & (blksize-1)){
		printk(KERN_INFO "elen & (blksize-1) != 0\n");
		return NULL;
	}
        nfrags = skb_cow_data(skb, 0, &trailer);
	skb->ip_summed = CHECKSUM_NONE;
        if(nfrags < 0){
                printk(KERN_INFO "nfrags < 0\n");
                return NULL;
        }
	if(unlikely(nfrags > SG_MAX)){
		printk(KERN_INFO "nfrags > SG_MAX\n");
		return NULL;
	}
        if(trailer == NULL){
                printk(KERN_INFO "trailer == NULL\n");
                return NULL;
        }
        skb_to_sgvec(skb, sg, 0, elen);
        err = ecb_aes_decrypt(key, sg, elen, ctx);
	//printk(KERN_INFO "DEBUG:ERR:%d\n",err);
	if(err < 0){
		printk(KERN_INFO "err < 0\n");
		return NULL;
	}
	if(skb_copy_bits(skb, skb->len - 1, &padlen, 1)){
		printk(KERN_INFO "skb_copy_bits error!\n");
		return NULL;
	}	
	if(padlen + 1 >=  elen){
		printk(KERN_INFO "(padlen + 1 + skb->len) != elen\n");
		printk(KERN_INFO "padlen:%d, skb->len:%d\n", padlen, skb->len);
		return NULL;
	}
	pskb_trim(skb, skb->len - padlen - 1);
	//printk(KERN_INFO "DEBUG:skb->len:%d\n",skb->len);
	//eth = eth_hdr(skb);
	//p = (unsigned char*)eth + sizeof(struct ethhdr);
	//printk(KERN_INFO "DEBUG:ID1:%d",*(unsigned char*)p);
        return skb;
}




struct ecb_des_ctx {
	struct crypto_skcipher* tfm;
	struct skcipher_request* req;
	struct completion complete;
	int err;
};

static void ecb_des_cb(struct crypto_async_request* req, int error) {
	struct ecb_des_ctx* ctx = req->data;//?ecb_des_ctx
	if (error == -EINPROGRESS) return;
	ctx->err = error;
	complete(&ctx->complete);
}

static void ecb_des_init(struct ecb_des_ctx* ctx) {
	ctx->tfm = crypto_alloc_skcipher("ecb(des)", 0, 0);
	ctx->req = skcipher_request_alloc(ctx->tfm, GFP_KERNEL);
	skcipher_request_set_callback(ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG, ecb_des_cb, ctx);
	init_completion(&ctx->complete);
}

static void ecb_des_cleanup(struct ecb_des_ctx* ctx) {
	skcipher_request_free(ctx->req);
	crypto_free_skcipher(ctx->tfm);
}

int ecb_des_encrypt(void* key, struct scatterlist* sg, unsigned int size, struct ecb_des_ctx* ctx) {
	int ret;
	crypto_skcipher_setkey(ctx->tfm, key, 8);
	skcipher_request_set_crypt(ctx->req, sg, sg, size, NULL);
	ret = crypto_skcipher_encrypt(ctx->req);
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion(&ctx->complete);
		ret = ctx->err;
	}
	return ret;
}

int ecb_des_decrypt(void* key, struct scatterlist* sg, unsigned int size, struct ecb_des_ctx* ctx) {
	int ret;
	crypto_skcipher_setkey(ctx->tfm, key, 8);
	skcipher_request_set_crypt(ctx->req, sg, sg, size, NULL);
	ret = crypto_skcipher_decrypt(ctx->req);
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion(&ctx->complete);
		ret = ctx->err;
	}
	return ret;
}

struct sk_buff* ecb_des_skb_encrypt(struct sk_buff* skb, unsigned char* KEY, struct ecb_des_ctx* ctx) {
	struct sk_buff* trailer;
	struct scatterlist sg[SG_MAX];
	unsigned char err;
	unsigned char* tail;
	unsigned char blksize;
	unsigned int clen;
	unsigned char nfrags;
	unsigned char i;
	unsigned char* key = KEY;
	if (skb == NULL) return NULL;
	clen = skb->len;
	if (clen < 46) {
		clen = 46;
	}
	blksize = ALIGN(8, 4);
	clen = ALIGN(clen + 1, blksize);
	nfrags = skb_cow_data(skb, clen - skb->len, &trailer);
	if (nfrags < 0) {
		printk(KERN_INFO "nfrags < 0\n");
		return NULL;
	}
	if (trailer == NULL) {
		printk(KERN_INFO "trailer == NULL\n");
		return NULL;
	}
	tail = skb_tail_pointer(trailer);
	for (i = 0; i < clen - skb->len - 1; i++)
		*(unsigned char*)(tail + i) = i + 1;
	*(unsigned char*)(tail + clen - skb->len - 1) = (clen - skb->len) - 1;
	pskb_put(skb, trailer, clen - skb->len);
	skb_to_sgvec(skb, sg, 0, clen);
	err = ecb_des_encrypt(key, sg, clen, ctx);
	if (err < 0) {
		printk(KERN_INFO "encrypt:err<0\n");
		return NULL;
	}
	return skb;
}

struct sk_buff* ecb_des_skb_decrypt(struct sk_buff* skb, unsigned char* KEY, struct ecb_des_ctx* ctx) {
	struct sk_buff* trailer;
	struct scatterlist sg[SG_MAX];
	unsigned char blksize;
	unsigned char err;
	unsigned int elen;
	unsigned char padlen;
	unsigned char nfrags;
	unsigned char* p;
	struct ethhdr* eth;
	unsigned char* key = KEY;
	if (skb == NULL) return NULL;
	elen = skb->len;
	blksize = ALIGN(8, 4);
	if (elen <= 0) {
		printk(KERN_INFO "elen <= 0\n");
		return NULL;
	}
	if (elen & (blksize - 1)) {
		printk(KERN_INFO "elen & (blksize-1) != 0\n");
		return NULL;
	}
	nfrags = skb_cow_data(skb, 0, &trailer);
	skb->ip_summed = CHECKSUM_NONE;
	if (nfrags < 0) {
		printk(KERN_INFO "nfrags < 0\n");
		return NULL;
	}
	if (unlikely(nfrags > SG_MAX)) {
		printk(KERN_INFO "nfrags > SG_MAX\n");
		return NULL;
	}
	if (trailer == NULL) {
		printk(KERN_INFO "trailer == NULL\n");
		return NULL;
	}
	skb_to_sgvec(skb, sg, 0, elen);
	err = ecb_des_decrypt(key, sg, elen, ctx);
	//printk(KERN_INFO "DEBUG:ERR:%d\n",err);
	if (err < 0) {
		printk(KERN_INFO "err < 0\n");
		return NULL;
	}
	if (skb_copy_bits(skb, skb->len - 1, &padlen, 1)) {
		printk(KERN_INFO "skb_copy_bits error!\n");
		return NULL;
	}
	if (padlen + 1 >= elen) {
		printk(KERN_INFO "(padlen + 1 + skb->len) != elen\n");
		printk(KERN_INFO "padlen:%d, skb->len:%d\n", padlen, skb->len);
		return NULL;
	}
	pskb_trim(skb, skb->len - padlen - 1);
	//printk(KERN_INFO "DEBUG:skb->len:%d\n",skb->len);
	//eth = eth_hdr(skb);
	//p = (unsigned char*)eth + sizeof(struct ethhdr);
	//printk(KERN_INFO "DEBUG:ID1:%d",*(unsigned char*)p);
	return skb;
}