#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *arp_pkt = (arp_pkt_t*)txbuf.data;
    // 填写arp报头
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    memcpy(&(arp_pkt->target_ip), target_ip, NET_IP_LEN);
    arp_pkt->opcode16 = swap16(ARP_REQUEST);

    // 将 ARP 报文发送出去
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    buf_init(&txbuf, sizeof(arp_pkt_t));
    arp_pkt_t *arp_pkt = (arp_pkt_t*)txbuf.data;
    // 填写arp报头
    memcpy(arp_pkt, &arp_init_pkt, sizeof(arp_pkt_t));
    memcpy(arp_pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_pkt->target_mac, target_mac, NET_MAC_LEN);
    arp_pkt->opcode16 = swap16(ARP_REPLY);

    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // 判断数据包是否完整
    if (buf->len < sizeof(arp_pkt_t)) {
        return;
    }

    // 报头检查
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    uint16_t opcode = swap16(arp_pkt->opcode16);
    if (swap16(arp_pkt->hw_type16) != ARP_HW_ETHER ||
        swap16(arp_pkt->pro_type16) != NET_PROTOCOL_IP ||
        arp_pkt->hw_len != NET_MAC_LEN || arp_pkt->pro_len != NET_IP_LEN ||
        !(opcode == ARP_REPLY || opcode == ARP_REQUEST))
    {
        return;
    }
    // 更新 ARP 表项
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);

    buf_t *buf_in_map = NULL;
    if ((buf_in_map = (buf_t *)map_get(&arp_buf, arp_pkt->sender_ip)) != NULL) 
    {
        ethernet_out(buf_in_map, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_pkt->sender_ip);
    } else if (opcode == ARP_REQUEST && memcmp(net_if_ip, arp_pkt->target_ip, NET_IP_LEN) == 0)
    {
        arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    // 根据 ip 查找 ARP
    uint8_t *target_mac = (uint8_t *)map_get(&arp_table, ip);
    if (target_mac != NULL)
    {
        ethernet_out(buf, target_mac, NET_PROTOCOL_IP);
        return;
    }

    // arp_buf 有包时，表示正在等待回应，不能再发送arp请求
    if (map_get(&arp_buf, ip) != NULL)
    {
        return;
    }
    // 缓存来自 ip 层的数据并发送 arp 请求
    map_set(&arp_buf, ip, buf);
    arp_req(ip);
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}