#include "http.h"
#include "tcp.h"
#include "net.h"
#include "assert.h"
#include <sys/stat.h>

#define TCP_FIFO_SIZE 40

// 使用一个 fifo 的队列缓存tcp连接
typedef struct http_fifo {
    tcp_connect_t* buffer[TCP_FIFO_SIZE];
    uint8_t front, tail, count;
} http_fifo_t;

static http_fifo_t http_fifo_v;

static void http_fifo_init(http_fifo_t* fifo) {
    fifo->count = 0;
    fifo->front = 0;
    fifo->tail = 0;
}

static int http_fifo_in(http_fifo_t* fifo, tcp_connect_t* tcp) {
    if (fifo->count >= TCP_FIFO_SIZE) {
        return -1;
    }
    fifo->buffer[fifo->front] = tcp;
    fifo->front++;
    if (fifo->front >= TCP_FIFO_SIZE) {
        fifo->front = 0;
    }
    fifo->count++;
    return 0;
}

static tcp_connect_t* http_fifo_out(http_fifo_t* fifo) {
    if (fifo->count == 0) {
        return NULL;
    }
    tcp_connect_t* tcp = fifo->buffer[fifo->tail];
    fifo->tail++;
    if (fifo->tail >= TCP_FIFO_SIZE) {
        fifo->tail = 0;
    }
    fifo->count--;
    return tcp;
}

// 函数的作用是从返回的http报文中读取一行
static size_t get_line(tcp_connect_t* tcp, char* buf, size_t size) {
    size_t i = 0;
    while (i < size) {
        char c;
        if (tcp_connect_read(tcp, (uint8_t*)&c, 1) > 0) {
            if (c == '\n') {
                break;
            }
            if (c != '\n' && c != '\r') {
                buf[i] = c;
                i++;
            }
        }
        net_poll();
    }
    buf[i] = '\0';
    return i;
}

// http 发送数据
static size_t http_send(tcp_connect_t* tcp, const char* buf, size_t size) {
    size_t send = 0;
    while (send < size) {
        send += tcp_connect_write(tcp, (const uint8_t*)buf + send, size - send);
        net_poll();
    }
    return send;
}

// 关闭http连接
static void close_http(tcp_connect_t* tcp) {
    tcp_connect_close(tcp);
    printf("http closed.\n");
}


// 发送url指定的文件
static void send_file(tcp_connect_t* tcp, const char* url) {
    FILE* file;
    uint32_t size;
    char file_path[255];
    char tx_buffer[1024];

    /*
    解析url路径，查看是否是查看HTTP_DOC_DIR目录下的文件
    如果不是，则发送404 NOT FOUND
    如果是，则用HTTP/1.0协议发送

    注意，本实验的WEB服务器网页存放在HTTP_DOC_DIR目录中
    */

    // TODO
    // 解析url路径,传进来的url是类似 /index.html
    sprintf(file_path, "%s%s", HTTP_DOC_DIR, url);
    printf("filepath: %s\n", file_path);
    // 查看是否是文件类型，如果不是，则发送404 NOT FOUND，返回404页面
    struct stat st;
    if (stat(file_path, &st) != 0) {
        sprintf(file_path, "%s/404page.html", HTTP_DOC_DIR);
        file = fopen(file_path, "rb");
        // 获取文件大小
        fseek(file, 0L, SEEK_END);
        size = (uint32_t)ftell(file);
        rewind(file);
        sprintf(tx_buffer, "HTTP/1.0 404 NOT FOUND\r\nContent-Length:%d\r\n\r\n", size);
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        goto send;
        return;
    }

    // 否则，读取文件内容，并发送；由于存在图片类型，需要二进制读
    file = fopen(file_path, "rb");
    // 获取文件大小
    fseek(file, 0L, SEEK_END);
    size = (uint32_t)ftell(file);
    rewind(file);
    // 发送 http 报头
    sprintf(tx_buffer, "HTTP/1.0 200 OK\r\nContent-Length:%d\r\n\r\n", size);
    http_send(tcp, tx_buffer, strlen(tx_buffer));
    // 读取文件内容并发送
    
send:
    while (!feof(file)) {
        size = fread(tx_buffer, 1, 1024, file);
        if (http_send(tcp, tx_buffer, size) <= 0) {
            fclose(file);
            return;
        }
    }
    fclose(file);
}

static void http_handler(tcp_connect_t* tcp, connect_state_t state) {
    if (state == TCP_CONN_CONNECTED) {
        http_fifo_in(&http_fifo_v, tcp);
        printf("http conntected.\n");
    } else if (state == TCP_CONN_DATA_RECV) {
    } else if (state == TCP_CONN_CLOSED) {
        printf("http closed.\n");
    } else {
        assert(0);
    }
}


// 在端口上创建服务器。

int http_server_open(uint16_t port) {
    if (!tcp_open(port, http_handler)) {
        return -1;
    }
    http_fifo_init(&http_fifo_v);
    return 0;
}

// 从FIFO取出请求并处理。新的HTTP请求时会发送到FIFO中等待处理。

void http_server_run(void) {
    tcp_connect_t* tcp;
    char url_path[255];
    char rx_buffer[1024];

    while ((tcp = http_fifo_out(&http_fifo_v)) != NULL) {
        int i;
        char* c = rx_buffer;

        /*
        1、调用get_line从rx_buffer中获取一行数据，如果没有数据，则调用close_http关闭tcp，并继续循环
        */

        // TODO
        if (get_line(tcp, rx_buffer, 1024) <= 0){
            close_http(tcp);
            continue;
        }

        printf("getline:%s\n", rx_buffer);

        /*
        2、检查是否有GET请求，如果没有，则调用close_http关闭tcp，并继续循环
        */

        // TODO
        // 比较前三个字符是否为 GET
        if (strncmp(rx_buffer, "GET", 3) != 0){
            close_http(tcp);
            continue;
        }

        /*
        3、解析GET请求的路径，注意跳过空格，找到GET请求的文件，调用send_file发送文件
        */

        // TODO
        // 第5个字节开始就是url_path
        c += 4;
        i = 0;
        while(*c != ' '){
            url_path[i++] = *(c++);
        }
        url_path[i] = '\0';
        // 使用send_file发送文件
        send_file(tcp, url_path);

        /*
        4、调用close_http关掉连接
        */

        // TODO
        close_http(tcp);

        printf("!! final close\n");
    }
}