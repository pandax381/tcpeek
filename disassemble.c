#include "tcpeek.h"

static uint8_t *
tcpeek_disassemble_ether(const uint8_t *packet, uint16_t plen, struct ether_header *dst) {
	struct ether_header *ether;

	ether = (struct ether_header *)packet;
	if(!ether || plen < sizeof(struct ether_header)) {
		return NULL;
	}
	if(ntohs(ether->ether_type) != ETHERTYPE_IP) {
		return NULL;
	}
	memcpy(dst, ether, sizeof(struct ether_header));
	return (uint8_t *)(ether + 1);
}

static uint8_t *
tcpeek_disassemble_sll(const uint8_t *packet, uint16_t plen, struct sll_header *dst) {
	struct sll_header *sll;

	sll = (struct sll_header *)packet;
	if(!sll || plen < sizeof(struct sll_header)) {
		return NULL;
	}
	if(ntohs(sll->sll_protocol) != ETHERTYPE_IP) {
		return NULL;
	}
	memcpy(dst, sll, sizeof(struct sll_header));
	return (uint8_t *)(sll + 1);
}

static uint8_t *
tcpeek_disassemble_datalink(const uint8_t *packet, int plen, int datalink, struct tcpeek_segment_datalink *dst) {
	switch(datalink) {
		case DLT_EN10MB:
			return tcpeek_disassemble_ether(packet, plen, &dst->hdr.ether);
		case DLT_LINUX_SLL:
			return tcpeek_disassemble_sll(packet, plen, &dst->hdr.sll);
	}
	return NULL; // does not reached.
}

static uint8_t *
tcpeek_disassemble_ip(const uint8_t *packet, uint16_t plen, int datalink, struct tcpeek_segment_ip *dst) {
	struct ip *ip;
	uint16_t hlen, sum;

	ip = (struct ip *)tcpeek_disassemble_datalink(packet, plen, datalink, &dst->datalink);
	if(!ip) {
		return NULL;
	}
	plen -= (caddr_t)ip - (caddr_t)packet;
	if(plen < sizeof(struct ip)) {
		return NULL;
	}
	hlen = ip->ip_hl << 2;
	if(plen < hlen || plen < ntohs(ip->ip_len)) {
		return NULL;
	}
	if(g.option.checksum & TCPEEK_CKSUM_IP) {
		sum = cksum16((uint16_t *)ip, hlen, 0);
		if(sum != 0) {
			syslog(LOG_WARNING, "%s [warning] IP checksum error. %04X (%04X)\n", __func__, sum, ip->ip_sum);
			return NULL;
		}
	}
	if(ip->ip_p != IPPROTO_TCP) {
		return NULL;
	}
	memcpy(&dst->hdr, ip, sizeof(struct ip));
	return (uint8_t *)((caddr_t)ip + hlen);
}

static uint8_t *
tcpeek_disassemble_tcp(const uint8_t *packet, uint16_t plen, int datalink, struct tcpeek_segment_tcp *dst) {
	struct tcphdr *tcphdr;
	struct ip *ip;
	uint16_t hlen, tcplen, sum;
	uint32_t pseudo = 0;

	tcphdr = (struct tcphdr *)tcpeek_disassemble_ip(packet, plen, datalink, &dst->ip);
	if(!tcphdr) {
		return NULL;
	}
	plen -= (caddr_t)tcphdr - (caddr_t)packet;
	if(plen < sizeof(struct tcphdr)) {
		return NULL;
	}
	hlen = tcphdr->th_off << 2;
	if(plen < hlen) {
		return NULL;
	}
	ip = &dst->ip.hdr;
	tcplen = ntohs(ip->ip_len) - (ip->ip_hl << 2);
	if(g.option.checksum & TCPEEK_CKSUM_TCP) {
		pseudo += ip->ip_src.s_addr >> 16;
		pseudo += ip->ip_src.s_addr & 0xffff;
		pseudo += ip->ip_dst.s_addr >> 16;
		pseudo += ip->ip_dst.s_addr & 0xffff;
		pseudo += htons(IPPROTO_TCP);
		pseudo += htons(tcplen);
		sum = cksum16((uint16_t *)tcphdr, tcplen, pseudo);
		if(sum != 0) {
			syslog(LOG_WARNING, "%s [warning] TCP checksum error. %04X (%04X)\n", __func__, sum, tcphdr->th_sum);
			return NULL;
		}
	}
	dst->psize = tcplen - hlen;
	memcpy(&dst->hdr, tcphdr, sizeof(struct tcphdr));
	return (uint8_t *)((caddr_t)tcphdr + hlen);
}

uint8_t *
tcpeek_disassemble(const uint8_t *data, uint16_t size, int datalink, struct tcpeek_segment *dst) {
	return tcpeek_disassemble_tcp(data, size, datalink, &dst->tcp);
}
