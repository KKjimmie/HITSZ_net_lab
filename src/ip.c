#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

// 标识
uint16_t send_id = 0;

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    if (buf->len < sizeof(ip_hdr_t))
        return;
    
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    // 报头检测
    if (ip_hdr->version != IP_VERSION_4 || swap16(ip_hdr->total_len16) > buf->len)
        return;

    uint16_t hdr_checksum16 = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    if (swap16(hdr_checksum16) != checksum16((uint16_t*)ip_hdr, sizeof(ip_hdr_t)))
        return;
    
    ip_hdr->hdr_checksum16 = hdr_checksum16;

    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0)
        return;
    
    uint16_t total_len = swap16(ip_hdr->total_len16);
    if (buf->len > total_len)
        buf_remove_padding(buf, buf->len - total_len);
    
    if (!(ip_hdr->protocol == NET_PROTOCOL_ICMP || ip_hdr->protocol == NET_PROTOCOL_UDP))
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);

    if (buf_remove_header(buf, sizeof(ip_hdr_t)) < 0)
    {
        fprintf(stderr, "ip_in(): buf_remove_header");
        return;
    }
    
    if (net_in(buf, ip_hdr->protocol, ip_hdr->src_ip) < 0)
        fprintf(stderr, "ip_in(): net_in");

}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    
    // 填写头部信息
    ip_hdr->hdr_len = 5;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = (mf == 0) ? swap16(buf->len) : swap16(IP_MAX_TRANSPRT_UNIT);
    ip_hdr->id16 = swap16(id);
    if (mf)
        ip_hdr->flags_fragment16 = (IP_MORE_FRAGMENT | swap16(offset / IP_HDR_OFFSET_PER_BYTE));
    else 
        ip_hdr->flags_fragment16 = swap16(offset / IP_HDR_OFFSET_PER_BYTE);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = swap16(checksum16((uint16_t*)ip_hdr, sizeof(ip_hdr_t)));

    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    if (buf->len <= IP_MAX_TRANSPRT_UNIT)
    {
        ip_fragment_out(buf, ip, protocol, send_id++, 0, 0);
    }
    else
    {  
        uint8_t len = buf->len;
        uint16_t no = 0; // 第几个分片
        while(len > IP_MAX_TRANSPRT_UNIT)
        {
            buf_init(&txbuf, IP_MAX_TRANSPRT_UNIT);
            memcpy(&txbuf, buf + no * IP_MAX_TRANSPRT_UNIT, IP_MAX_TRANSPRT_UNIT);
            ip_fragment_out(&txbuf, ip, protocol, send_id, no * IP_MAX_TRANSPRT_UNIT, 1);
            len -= IP_MAX_TRANSPRT_UNIT;
            no += 1;
        }
        buf_init(&txbuf, len);
        memcpy(&txbuf, buf + no * IP_MAX_TRANSPRT_UNIT, len);
        ip_fragment_out(&txbuf, ip, protocol, send_id, no * IP_MAX_TRANSPRT_UNIT, 0);
        send_id++;
    }
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}