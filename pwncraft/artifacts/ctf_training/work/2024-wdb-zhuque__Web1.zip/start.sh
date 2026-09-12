#!/bin/bash

# 设置颜色变量
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# 启动 Apache HTTPd 服务器
echo -e "${GREEN}Starting Apache HTTPd...${NC}"
httpd-foreground > /var/log/apache.log 2>&1 &
HTTPD_PID=$!
echo "Apache HTTPd started with PID $HTTPD_PID"

# 启动 Node.js 应用程序
echo -e "${GREEN}Starting Node.js app...${NC}"
node /app/app.js > /var/log/node.log 2>&1 &
NODE_PID=$!
echo "Node.js app started with PID $NODE_PID"

# 显示输出日志
tail -f /var/log/node.log &
TAIL_PID=$!

# 等待所有子进程终止
wait $HTTPD_PID $NODE_PID $TAIL_PID

# 输出退出信息
echo -e "${RED}All processes have exited${NC}"