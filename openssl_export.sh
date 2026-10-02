#!/bin/bash

export PATH=/opt/openssl-3.5/bin:$PATH
export LD_LIBRARY_PATH=/opt/openssl-3.5/lib64:$LD_LIBRARY_PATH
openssl version   # 應該顯示 OpenSSL 3.5.x