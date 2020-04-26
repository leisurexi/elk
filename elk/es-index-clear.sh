# /bin/bash
# es-index-clear
# 只保留15天内的日志索引
LAST_DATA=`date -d "-15 days" "+%Y.%m.%d"`
# 删除索引
curl -XDELETE 'http://192.168.239.133:9200/*-'${LAST_DATA}'*'
