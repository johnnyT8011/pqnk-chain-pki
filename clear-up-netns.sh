#!/bin/bash
# teardown-netns.sh
ip netns delete client_ns 2>/dev/null
ip netns delete server_ns 2>/dev/null
echo "netns 已清除"