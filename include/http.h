#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>
/**
 * @brief web网页文件在路径
 *        调试时建议改为绝对路径
 * 
 */
#define HTTP_DOC_DIR               "../htmldocs"
// #define HTTP_DOC_DIR               "Absolute path"

int http_server_open(uint16_t port);
void http_server_run(void);

#endif
