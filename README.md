# 前言

本篇文章主要介绍在两台机器上使用 Docker 搭建 ELK。

# 正文

## 环境

* CentOS 7.7 系统

* Docker version 19.03.8

* docker-compose version 1.23.2

## 系统设置

`vim` 编辑 `/etc/security/limits.conf`，在末尾加上：

```shell
* soft nofile 65536
* hard nofile 65536
* soft nproc 4096
* hard nproc 4096
```

`vim` 编辑 `/etc/sysctl.conf`，在末尾加上：

```shell
vm.max_map_count = 655360
```

执行 `sysctl -p` 命令是配置生效。

## Elasticsearch 搭建

> 注意：如果用非 Docker 搭建，是不能用 `root` 用户去启动的。

> 由于我是用虚拟机搭建的，我的机器只能开两台，所以只有一个主节点和一个数据节点；在生产环境中最少要3台，防止脑裂问题。

> 注意：如果开启了防火墙，需要执行以下命令开放 9200 和 9300 端口号。
>
> ```shell
> firewall-cmd --zone=public --add-port=9200/tcp --permanent
> firewall-cmd --zone=public --add-port=9300/tcp --permanent
> ```

### 主节点

首先设置主节点的配置文件 `elasticsearch.yml`，如下：

```yaml
# ======================== Elasticsearch Configuration =========================
#
# NOTE: Elasticsearch comes with reasonable defaults for most settings.
#       Before you set out to tweak and tune the configuration, make sure you
#       understand what are you trying to accomplish and the consequences.
#
# The primary way of configuring a node is via this file. This template lists
# the most important settings you may want to configure for a production cluster.
#
# Please consult the documentation for further information on configuration options:
# https://www.elastic.co/guide/en/elasticsearch/reference/index.html
#
# ---------------------------------- Cluster -----------------------------------
#
# Use a descriptive name for your cluster:

cluster.name: es-cluster
#
# ------------------------------------ Node ------------------------------------
#
# Use a descriptive name for the node:

node.name: es-master

node.master: true

node.data: false

#node.ingest: false

#node.ml: false
#xpack.ml.enabled: true

#cluster.remote.connect: false
#
# Add custom attributes to the node:
#
#node.attr.rack: r1
#
# ----------------------------------- Paths ------------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
#
#path.data: /path/to/data
#
# Path to log files:
#
#path.logs: /path/to/logs
#
# ----------------------------------- Memory -----------------------------------
#
# Lock the memory on startup:
#
#bootstrap.memory_lock: true
#
# Make sure that the heap size is set to about half the memory available
# on the system and that the owner of the process is allowed to use this
# limit.
#
# Elasticsearch performs poorly when the system is swapping the memory.
#
# ---------------------------------- Network -----------------------------------
#
# Set the bind address to a specific IP (IPv4 or IPv6):

network.host: 0.0.0.0
network.publish_host: 192.168.239.133
#
# Set a custom port for HTTP:

http.port: 9200

transport.tcp.port: 9300
#
# For more information, consult the network module documentation.
#
# --------------------------------- Discovery ----------------------------------
#
# Pass an initial list of hosts to perform discovery when this node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#
discovery.seed_hosts:
  - 192.168.239.133
  - 192.168.239.131
#
# Bootstrap the cluster using an initial set of master-eligible nodes:

cluster.initial_master_nodes:
  - es-master
#  - es-node2
#  - es-node3
#
# For more information, consult the discovery and cluster formation module documentation.
#
# ---------------------------------- Gateway -----------------------------------
#
# Block initial recovery after a full cluster restart until N nodes are started:
#
#gateway.recover_after_nodes: 2
#
# For more information, consult the gateway module documentation.
#
# ---------------------------------- Various -----------------------------------
#
# Require explicit names when deleting indices:
#
#action.destructive_requires_name: true


http.cors.enabled: true
http.cors.allow-origin: "*"
```

然后编写主节点的 `docker-compose.yml`，如下：

```yaml
version: "3"
services:
  es-master:
    container_name: es-master
    hostname: es-master
    image: leisurexi/elasticsearch:7.1.0
    privileged: true
    ports:
      - 9200:9200
      - 9300:9300
    volumes:
      - ./elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml
      - ./data:/usr/share/elasticsearch/data
      - ./logs:/usr/share/elasticsearch/logs
    environment:
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    ulimits:
      memlock:
        soft: -1
        hard: -1
```

> 注意：这个镜像是我自己 Docker Hup 上的，你可以换成官方的。（我的镜像和官方的一样，只是嫌每次下载太难，就把官方的镜像改了 `tag` 上传到自己的 Docker Hup 上了）

接着执行以下命令启动容器

```shell
docker-compose up -d
```

如果出现下图所示的错误，可以使用 `chmod 777 logs` 和 `chmod 777 data` 来修改文件夹的权限，即可正常启动。

![](http://ww1.sinaimg.cn/large/006Vpl27ly1ge66se2rosj30tc06adgb.jpg)

然后进入容器，创建默认的用户和分组

```shell
# 进入容器
docker exec -it es-master bash
```

```shell
# 激活默认用户并设置密码
bin/elasticsearch-setup-passwords interactive
```

### 数据节点

首先设置数据节点的配置文件 `elasticsearch.yml`，如下：

```yaml
# ======================== Elasticsearch Configuration =========================
#
# NOTE: Elasticsearch comes with reasonable defaults for most settings.
#       Before you set out to tweak and tune the configuration, make sure you
#       understand what are you trying to accomplish and the consequences.
#
# The primary way of configuring a node is via this file. This template lists
# the most important settings you may want to configure for a production cluster.
#
# Please consult the documentation for further information on configuration options:
# https://www.elastic.co/guide/en/elasticsearch/reference/index.html
#
# ---------------------------------- Cluster -----------------------------------
#
# Use a descriptive name for your cluster:

cluster.name: es-cluster
#
# ------------------------------------ Node ------------------------------------
#
# Use a descriptive name for the node:

node.name: es-data

node.master: true

node.data: true

#node.ingest: false

#node.ml: false
#xpack.ml.enabled: true

#cluster.remote.connect: false
#
# Add custom attributes to the node:
#
#node.attr.rack: r1
#
# ----------------------------------- Paths ------------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
#
#path.data: /path/to/data
#
# Path to log files:
#
#path.logs: /path/to/logs
#
# ----------------------------------- Memory -----------------------------------
#
# Lock the memory on startup:
#
#bootstrap.memory_lock: true
#
# Make sure that the heap size is set to about half the memory available
# on the system and that the owner of the process is allowed to use this
# limit.
#
# Elasticsearch performs poorly when the system is swapping the memory.
#
# ---------------------------------- Network -----------------------------------
#
# Set the bind address to a specific IP (IPv4 or IPv6):

network.host: 0.0.0.0
network.publish_host: 192.168.239.131
#
# Set a custom port for HTTP:

http.port: 9200

transport.tcp.port: 9300
#
# For more information, consult the network module documentation.
#
# --------------------------------- Discovery ----------------------------------
#
# Pass an initial list of hosts to perform discovery when this node is started:
# The default list of hosts is ["127.0.0.1", "[::1]"]
#
discovery.seed_hosts:
  - 192.168.239.133
  - 192.168.239.131
#
# Bootstrap the cluster using an initial set of master-eligible nodes:

cluster.initial_master_nodes:
  - es-master
#  - es-node2
#  - es-node3
#
# For more information, consult the discovery and cluster formation module documentation.
#
# ---------------------------------- Gateway -----------------------------------
#
# Block initial recovery after a full cluster restart until N nodes are started:
#
#gateway.recover_after_nodes: 2
#
# For more information, consult the gateway module documentation.
#
# ---------------------------------- Various -----------------------------------
#
# Require explicit names when deleting indices:
#
#action.destructive_requires_name: true


http.cors.enabled: true
http.cors.allow-origin: "*"
```

然后编写数据节点的 `docker-compose.yml`，如下：

```yaml
version: "3"
services:
  es-master:
    container_name: es-data
    hostname: es-data
    image: leisurexi/elasticsearch:7.1.0
    privileged: true
    ports:
      - 9200:9200
      - 9300:9300
    volumes:
      - ./elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml
      - ./data:/usr/share/elasticsearch/data
      - ./logs:/usr/share/elasticsearch/logs
    environment:
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    ulimits:
      memlock:
        soft: -1
        hard: -1
```

接着像上面主节点一样启动就行了，然后访问主节点的 `http://192.168.239.133:9200/_cat/nodes` API 地址，如下图所示就代表 Elasticsearch 集群搭建成功了。

![](http://ww1.sinaimg.cn/large/006Vpl27ly1ge6at2a8asj30c001xweb.jpg)

## Kibana 搭建

> 因为主节点负责集群范围内的轻量级操作，例如创建或删除索引，跟踪哪些节点是集群的一部分以及确定将哪些碎片分配给哪些节点；所以将 Kibana 跟主节点放在一台机器上。

> 注意：如果开启了防火墙，需要执行以下命令开放 5601 端口号。
>
> ```shell
> firewall-cmd --zone=public --add-port=5601/tcp --permanent
> ```

首先是 Kibana 的配置文件 `Kibana.yml`，如下：

```yaml
# Kibana is served by a back end server. This setting specifies the port to use.
server.port: 5601

# Specifies the address to which the Kibana server will bind. IP addresses and host names are both valid values.
# The default is 'localhost', which usually means remote machines will not be able to connect.
# To allow connections from remote users, set this parameter to a non-loopback address.
server.host: "0.0.0.0"

# Enables you to specify a path to mount Kibana at if you are running behind a proxy.
# Use the `server.rewriteBasePath` setting to tell Kibana if it should remove the basePath
# from requests it receives, and to prevent a deprecation warning at startup.
# This setting cannot end in a slash.
#server.basePath: ""

# Specifies whether Kibana should rewrite requests that are prefixed with
# `server.basePath` or require that they are rewritten by your reverse proxy.
# This setting was effectively always `false` before Kibana 6.3 and will
# default to `true` starting in Kibana 7.0.
#server.rewriteBasePath: false

# The maximum payload size in bytes for incoming server requests.
#server.maxPayloadBytes: 1048576

# The Kibana server's name.  This is used for display purposes.
#server.name: "your-hostname"

# The URLs of the Elasticsearch instances to use for all your queries.
elasticsearch.hosts: ["http://192.168.239.133:9200", "http://192.168.239.131:9200"]

# When this setting's value is true Kibana uses the hostname specified in the server.host
# setting. When the value of this setting is false, Kibana uses the hostname of the host
# that connects to this Kibana instance.
#elasticsearch.preserveHost: true

# Kibana uses an index in Elasticsearch to store saved searches, visualizations and
# dashboards. Kibana creates a new index if the index doesn't already exist.
#kibana.index: ".kibana"

# The default application to load.
#kibana.defaultAppId: "home"

# If your Elasticsearch is protected with basic authentication, these settings provide
# the username and password that the Kibana server uses to perform maintenance on the Kibana
# index at startup. Your Kibana users still need to authenticate with Elasticsearch, which
# is proxied through the Kibana server.
#elasticsearch.username: "user"
#elasticsearch.password: "pass"

# Enables SSL and paths to the PEM-format SSL certificate and SSL key files, respectively.
# These settings enable SSL for outgoing requests from the Kibana server to the browser.
#server.ssl.enabled: false
#server.ssl.certificate: /path/to/your/server.crt
#server.ssl.key: /path/to/your/server.key

# Optional settings that provide the paths to the PEM-format SSL certificate and key files.
# These files validate that your Elasticsearch backend uses the same key files.
#elasticsearch.ssl.certificate: /path/to/your/client.crt
#elasticsearch.ssl.key: /path/to/your/client.key

# Optional setting that enables you to specify a path to the PEM file for the certificate
# authority for your Elasticsearch instance.
#elasticsearch.ssl.certificateAuthorities: [ "/path/to/your/CA.pem" ]

# To disregard the validity of SSL certificates, change this setting's value to 'none'.
#elasticsearch.ssl.verificationMode: full

# Time in milliseconds to wait for Elasticsearch to respond to pings. Defaults to the value of
# the elasticsearch.requestTimeout setting.
#elasticsearch.pingTimeout: 1500

# Time in milliseconds to wait for responses from the back end or Elasticsearch. This value
# must be a positive integer.
#elasticsearch.requestTimeout: 30000

# List of Kibana client-side headers to send to Elasticsearch. To send *no* client-side
# headers, set this value to [] (an empty list).
#elasticsearch.requestHeadersWhitelist: [ authorization ]

# Header names and values that are sent to Elasticsearch. Any custom headers cannot be overwritten
# by client-side headers, regardless of the elasticsearch.requestHeadersWhitelist configuration.
#elasticsearch.customHeaders: {}

# Time in milliseconds for Elasticsearch to wait for responses from shards. Set to 0 to disable.
#elasticsearch.shardTimeout: 30000

# Time in milliseconds to wait for Elasticsearch at Kibana startup before retrying.
#elasticsearch.startupTimeout: 5000

# Logs queries sent to Elasticsearch. Requires logging.verbose set to true.
#elasticsearch.logQueries: false

# Specifies the path where Kibana creates the process ID file.
#pid.file: /var/run/kibana.pid

# Enables you specify a file where Kibana stores log output.
#logging.dest: stdout

# Set the value of this setting to true to suppress all logging output.
#logging.silent: false

# Set the value of this setting to true to suppress all logging output other than error messages.
#logging.quiet: false

# Set the value of this setting to true to log all events, including system usage information
# and all requests.
#logging.verbose: false

# Set the interval in milliseconds to sample system and process performance
# metrics. Minimum is 100ms. Defaults to 5000.
#ops.interval: 5000

# Specifies locale to be used for all localizable strings, dates and number formats.
i18n.locale: "zh-CN"
```

然后是 `docker-compose.yml` 文件的编写，如下：

```yaml
version: "3"
services:
  kibana:
    container_name: kibana
    hostname: kibana
    image: leisurexi/kibana:7.1.0
    ports:
      - 5601:5601
    volumes:
      - ./kibana.yml:/usr/share/kibana/config/kibana.yml
```

> 注意：这个镜像是我自己 Docker Hup 上的，你可以换成官方的。

接着像 Elasticsearch 几点一样启动就可以了。

我们访问 Kibana 节点的 5601 端口就可以看到界面了，接下来执行 `GET _cluster/health` 查看 ES 集群的健康状况，来验证 Kibana 是否可以正常工作。

![](http://ww1.sinaimg.cn/large/006Vpl27ly1ge6bemwkihj30sq0ekt9s.jpg)

如上图一样就代表你已经 kibana 已经搭建成功了。

## logstash 搭建

> logstash 在 ES 的数据节点上搭建。

> 注意：如果开启了防火墙，需要执行以下命令开放 4560 和 5044 端口号。
>
> ```shell
> firewall-cmd --zone=public --add-port=4560/tcp --permanent
> firewall-cmd --zone=public --add-port=5044/tcp --permanent
> ```

首先是 logstash 的全局配置文件 `logstash.yml`，如下：

```yaml
# Settings file in YAML
#
# Settings can be specified either in hierarchical form, e.g.:
#
#   pipeline:
#     batch:
#       size: 125
#       delay: 5
#
# Or as flat keys:
#
#   pipeline.batch.size: 125
#   pipeline.batch.delay: 5
#
# ------------  Node identity ------------
#
# Use a descriptive name for the node:
#
# node.name: test
#
# If omitted the node name will default to the machine's host name
#
# ------------ Data path ------------------
#
# Which directory should be used by logstash and its plugins
# for any persistent needs. Defaults to LOGSTASH_HOME/data
#
# path.data:
#
# ------------ Pipeline Settings --------------
#
# The ID of the pipeline.
#
# pipeline.id: main
#
# Set the number of workers that will, in parallel, execute the filters+outputs
# stage of the pipeline.
#
# This defaults to the number of the host's CPU cores.
#
# pipeline.workers: 2
#
# How many events to retrieve from inputs before sending to filters+workers
#
# pipeline.batch.size: 125
#
# How long to wait in milliseconds while polling for the next event
# before dispatching an undersized batch to filters+outputs
#
# pipeline.batch.delay: 50
#
# Force Logstash to exit during shutdown even if there are still inflight
# events in memory. By default, logstash will refuse to quit until all
# received events have been pushed to the outputs.
#
# WARNING: enabling this can lead to data loss during shutdown
#
# pipeline.unsafe_shutdown: false
#
# ------------ Pipeline Configuration Settings --------------
#
# Where to fetch the pipeline configuration for the main pipeline
#
# path.config:
#
# Pipeline configuration string for the main pipeline
#
# config.string:
#
# At startup, test if the configuration is valid and exit (dry run)
#
# config.test_and_exit: false
#
# Periodically check if the configuration has changed and reload the pipeline
# This can also be triggered manually through the SIGHUP signal
#
# config.reload.automatic: false
#
# How often to check if the pipeline configuration has changed (in seconds)
#
# config.reload.interval: 3s
#
# Show fully compiled configuration as debug log message
# NOTE: --log.level must be 'debug'
#
# config.debug: false
#
# When enabled, process escaped characters such as \n and \" in strings in the
# pipeline configuration files.
#
# config.support_escapes: false
#
# ------------ Module Settings ---------------
# Define modules here.  Modules definitions must be defined as an array.
# The simple way to see this is to prepend each `name` with a `-`, and keep
# all associated variables under the `name` they are associated with, and
# above the next, like this:
#
# modules:
#   - name: MODULE_NAME
#     var.PLUGINTYPE1.PLUGINNAME1.KEY1: VALUE
#     var.PLUGINTYPE1.PLUGINNAME1.KEY2: VALUE
#     var.PLUGINTYPE2.PLUGINNAME1.KEY1: VALUE
#     var.PLUGINTYPE3.PLUGINNAME3.KEY1: VALUE
#
# Module variable names must be in the format of
#
# var.PLUGIN_TYPE.PLUGIN_NAME.KEY
#
# modules:
#
# ------------ Cloud Settings ---------------
# Define Elastic Cloud settings here.
# Format of cloud.id is a base64 value e.g. dXMtZWFzdC0xLmF3cy5mb3VuZC5pbyRub3RhcmVhbCRpZGVudGlmaWVy
# and it may have an label prefix e.g. staging:dXMtZ...
# This will overwrite 'var.elasticsearch.hosts' and 'var.kibana.host'
# cloud.id: <identifier>
#
# Format of cloud.auth is: <user>:<pass>
# This is optional
# If supplied this will overwrite 'var.elasticsearch.username' and 'var.elasticsearch.password'
# If supplied this will overwrite 'var.kibana.username' and 'var.kibana.password'
# cloud.auth: elastic:<password>
#
# ------------ Queuing Settings --------------
#
# Internal queuing model, "memory" for legacy in-memory based queuing and
# "persisted" for disk-based acked queueing. Defaults is memory
#
# queue.type: memory
#
# If using queue.type: persisted, the directory path where the data files will be stored.
# Default is path.data/queue
#
# path.queue:
#
# If using queue.type: persisted, the page data files size. The queue data consists of
# append-only data files separated into pages. Default is 64mb
#
# queue.page_capacity: 64mb
#
# If using queue.type: persisted, the maximum number of unread events in the queue.
# Default is 0 (unlimited)
#
# queue.max_events: 0
#
# If using queue.type: persisted, the total capacity of the queue in number of bytes.
# If you would like more unacked events to be buffered in Logstash, you can increase the
# capacity using this setting. Please make sure your disk drive has capacity greater than
# the size specified here. If both max_bytes and max_events are specified, Logstash will pick
# whichever criteria is reached first
# Default is 1024mb or 1gb
#
# queue.max_bytes: 1024mb
#
# If using queue.type: persisted, the maximum number of acked events before forcing a checkpoint
# Default is 1024, 0 for unlimited
#
# queue.checkpoint.acks: 1024
#
# If using queue.type: persisted, the maximum number of written events before forcing a checkpoint
# Default is 1024, 0 for unlimited
#
# queue.checkpoint.writes: 1024
#
# If using queue.type: persisted, the interval in milliseconds when a checkpoint is forced on the head page
# Default is 1000, 0 for no periodic checkpoint.
#
# queue.checkpoint.interval: 1000
#
# ------------ Dead-Letter Queue Settings --------------
# Flag to turn on dead-letter queue.
#
# dead_letter_queue.enable: false

# If using dead_letter_queue.enable: true, the maximum size of each dead letter queue. Entries
# will be dropped if they would increase the size of the dead letter queue beyond this setting.
# Default is 1024mb
# dead_letter_queue.max_bytes: 1024mb

# If using dead_letter_queue.enable: true, the directory path where the data files will be stored.
# Default is path.data/dead_letter_queue
#
# path.dead_letter_queue:
#
# ------------ Metrics Settings --------------
#
# Bind address for the metrics REST endpoint
#
# http.host: "127.0.0.1"
#
# Bind port for the metrics REST endpoint, this option also accept a range
# (9600-9700) and logstash will pick up the first available ports.
#
# http.port: 9600-9700
#
# ------------ Debugging Settings --------------
#
# Options for log.level:
#   * fatal
#   * error
#   * warn
#   * info (default)
#   * debug
#   * trace
#
# log.level: info
# path.logs:
#
# ------------ Other Settings --------------
#
# Where to find custom plugins
# path.plugins: []
#
# ------------ X-Pack Settings (not applicable for OSS build)--------------
#
# X-Pack Monitoring
# https://www.elastic.co/guide/en/logstash/current/monitoring-logstash.html
xpack.monitoring.enabled: true
#xpack.monitoring.elasticsearch.username: logstash_system
#xpack.monitoring.elasticsearch.password: password
xpack.monitoring.elasticsearch.hosts: ["http://192.168.239.133:9200", "http://192.168.239.131:9200"]
#xpack.monitoring.elasticsearch.ssl.certificate_authority: [ "/path/to/ca.crt" ]
#xpack.monitoring.elasticsearch.ssl.truststore.path: path/to/file
#xpack.monitoring.elasticsearch.ssl.truststore.password: password
#xpack.monitoring.elasticsearch.ssl.keystore.path: /path/to/file
#xpack.monitoring.elasticsearch.ssl.keystore.password: password
#xpack.monitoring.elasticsearch.ssl.verification_mode: certificate
#xpack.monitoring.elasticsearch.sniffing: false
#xpack.monitoring.collection.interval: 10s
#xpack.monitoring.collection.pipeline.details.enabled: true
#
# X-Pack Management
# https://www.elastic.co/guide/en/logstash/current/logstash-centralized-pipeline-management.html
xpack.management.enabled: false
#xpack.management.pipeline.id: ["main", "apache_logs"]
#xpack.management.elasticsearch.username: logstash_admin_user
#xpack.management.elasticsearch.password: password
#xpack.management.elasticsearch.hosts: ["https://es1:9200", "https://es2:9200"]
#xpack.management.elasticsearch.ssl.certificate_authority: [ "/path/to/ca.crt" ]
#xpack.management.elasticsearch.ssl.truststore.path: /path/to/file
#xpack.management.elasticsearch.ssl.truststore.password: password
#xpack.management.elasticsearch.ssl.keystore.path: /path/to/file
#xpack.management.elasticsearch.ssl.keystore.password: password
#xpack.management.elasticsearch.ssl.verification_mode: certificate
#xpack.management.elasticsearch.sniffing: false
#xpack.management.logstash.poll_interval: 5s

```

然后是自定义的 logstash 的配置文件 `logstash.conf`，如下：

```yaml
input {
  tcp {
    mode => "server"
    host => "0.0.0.0"
    port => 4560
    codec => json_lines
  }
}
output {
  elasticsearch {
    hosts => "http://192.168.239.133:9200"
    index => "log-%{+YYYY.MM.dd}"
  }
}

```

> 上面文件的大概意思就是监听 4560 端口，然后写入 ES，索引名称就是 log 前缀加上日期；每天都会创建一个新的索引。 

然后是 `docker-compose.yml`，如下：

```yaml
version: "3"
services:
  logstash:
    container_name: logstash
    hostname: logstash
    image: leisurexi/logstash:7.1.0
    command: logstash -f ./config/logstash.conf
    volumes:
      - ./logstash.conf:/usr/share/logstash/config/logstash.conf
      - ./logstash.yml:/usr/share/logstash/config/logstash.yml
    environment:
      - elasticsearch.hosts=http://192.168.239.133:9200
    ports:
      - 4560:4560
      - 5044:5044
```

最后像上面启动 ES 一样，启动 logstash 即可。

## 定期删除索引

如果长时间运行，会有磁盘满的而无法写入 ES 的情况，所以得定时删除不怎么重要的索引数据；如下，可以通过定时脚本来实现。

我们先写个删除15天前索引的脚本 `es-index-clear.sh`，如下：

```shell
# /bin/bash
# es-index-clear
# 只保留15天内的日志索引
LAST_DATA=`date -d "-15 days" "+%Y.%m.%d"`
# 删除索引
curl -XDELETE 'http://192.168.239.133:9200/*-'${LAST_DATA}'*'
```

然后利用 `crontab` 去添加定时任务，首先执行 `crontab -e`，然后添加以下内容：

```shell
0 1 * * * /opt/elk/es-index-clear.sh
```

> 该定时会在每天的凌晨1点执行，后面换成你自己脚本所在的绝对路径即可。

可以执行 `tail -f /var/log/cron`，查看定时任务的日志。

## 测试

我们新建一个 spring-boot 应用，添加 `logstash` 的依赖，如下：

```xml
<dependency>
    <groupId>net.logstash.logback</groupId>
    <artifactId>logstash-logback-encoder</artifactId>
    <version>5.3</version>
</dependency>
```

然后新建一个 `logback.xml` 放在 `resources` 目录下，内容如下：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE configuration>
<configuration>
    <include resource="org/springframework/boot/logging/logback/defaults.xml"/>
    <include resource="org/springframework/boot/logging/logback/console-appender.xml"/>
    <!--应用名称-->
    <property name="APP_NAME" value="log"/>

    <!--输出到logstash的appender-->
    <appender name="LOGSTASH" class="net.logstash.logback.appender.LogstashTcpSocketAppender">
        <!--可以访问的logstash日志收集端口-->
        <destination>192.168.239.131:4560</destination>
        <encoder charset="UTF-8" class="net.logstash.logback.encoder.LogstashEncoder"/>
    </appender>

    <root level="INFO">
        <appender-ref ref="CONSOLE"/>
        <appender-ref ref="LOGSTASH"/>
    </root>

</configuration>
```

接着编写一个定时任务，Java 代码如下：

```java
@EnableScheduling
@Configuration
public class LogScheduler {

    private static Logger log = LoggerFactory.getLogger(LogScheduler.class);

    @Scheduled(cron = " 0/30 * * * * ? ")
    public void doTiming() {
        log.info("ELK测试日志");
    }

}
```

> 该定时任务每30秒输出一条日志。

最后我们查看 kibana 的界面就可以看到啦！

![](http://ww1.sinaimg.cn/large/006Vpl27ly1ge7i03qcflj31gq0o2n38.jpg)

# 总结

本次只是简单的搭建了 ELK，如果要在生成环境上使用，还需要做很多修改；例如，ES 开启安全认证，端口不可直接暴露在公网上，索引最好使用模板创建等。

最后本篇文章的代码和 ELK 的配置文件，我都上传到 [https://github.com/leisurexi/elk](https://github.com/leisurexi/elk)。**访问新博客地址，观看效果更佳 [https://leisurexi.github.io/](https://leisurexi.github.io/)**

> 注意：Github 上的 `docker-compose.yml` 我是和在一起写的，文章中是分开写的，为了更清晰一点。 

