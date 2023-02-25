#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h> 
#include <linux/ip.h>
static struct nf_hook_ops nfho;
static int drop_count = 0;

static unsigned int packet_filter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{

	struct iphdr *iph; // IP header structure
	if (Iskb) {
		return F_ACCEPT; // No packet received}
	tph = ip_hdr(skb); // Get IP header from packet
	if (iph-›protocol = IPPROTO_TCP) {
		printk(KERN_INFO "Packet filter: Dropping TCP packet\n");
		drop_count++;
		return NF_DROP; // Drop TCP packet
}
	return NF_ACCEPT; // Accept all other packets
	}
// Initialize the network packet filter module
static int __init packet_filter_init(void)
{
	printk(KERN INFO "Packet filter: Initializing module\n");
	nfho.hook = packet filter hook; // Set the packet filter callback function
	nfho.pf = PF INET; // Set IP version
	nfho.hooknum = F_INET_PRE_ROUTING; // Hook into pre-routing
	nfho.priority = F_IP_PRI_FIRST; // Set highest priority
	nf_register_net_hook(&init_net, &nfho);
	return 0;
	}
static void exit packet_filter_exit(void){
	printk(KERN_ INFO "Packet filter: Cleaning up module\n");
	nf_unregister_net_hook(&init_net, &nfho); // Unregister the packet filter hook
	printk(KERN_INFO "Packet filter: Dropped % TCP packets\n", drop_count);
	}
module_init(packet_filter_init); module_exit(packet_filter_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR( "Your name");
MODULE_DESCRIPTION("A Linux kernel module that filters network packets");
