OpenContrail Troubleshoot

## 1 Configuration API Server

### 1.1 Data Flow

Here is an example of post request to create and object.
* A request is sent by the client to API server.
* API server
  * writes to Cassandra database to create object,
  * publishes to RabbitMQ,
  * reply to the client.
* RabbitMQ sends notification to all API servers.
* Once API server receives notification from RabbitMQ, it publishes data to local IF-MAP server.

### 1.2 Relations

API server depends on the following services.
* Cassandra database
* RabbitMQ message bus
* Zookeeper
* IF-MAP server

All services have to be running properly prior to the start of API server.

### 1.3 Cassandra
* Configuration files
  /etc/cassandra/*

* Log files
  /var/log/cassandra/*

* Process
```
# ps ax | grep cassandra
```

* Port and address binding
```
# netstat -lanp | grep LISTEN | grep <PID>
```

* Diagnostic tool
```
# nodetool status
```

### 1.4 RabbitMQ
* Configuration files
  /etc/rabbitmq/*

* Log files
  /var/log/rabbitmq/*

* Process
```
ps ax | grep rabbitmq
```

* Port and address binding
```
# netstat -lanp | grep LISTEN | grep <PID>
```

* Diagnostic tool
```
# rabbitmqctl status
# rabbitmqctl cluster_status
```

### 1.5 Zookeeper
* Configuration files
  /etc/zookeeper/conf/*

* Log files
  /var/log/zookeeper/*

* Process
```
ps ax | grep zookeeper
```

* Service
```
# service zookeeper status
```

* Port and address binding
```
# netstat -lanp | grep LISTEN | grep <PID>
```

### 1.6 IF-MAP Server
* Configuration files
  /etc/ifmap-server/*

* Log files
  /var/log/contrail/ifmap*

* Process
```
# ps ax | grep ifmap
```

* Service
```
# service ifmap status
```

* Port and address binding
```
# netstat -lanp | grep LISTEN | grep <PID>
```



##  2 Schema Transformer

### 2.1 Data Flow

Schema transformer subscribes to IF-MAP server to get notication of configuration changes. Here is an example when a new virtual network is created by user.
* Get notification from IF-MAP server.
* Send request to configuration API server to create routing instance and route target for the newly created virtual network.

### 2.2 Relations

Schema transformer depends on the following services.
* IF-MAP server
* Zookeeper
* Configuration API server


## 3. Service Monitor

### 3.1 Data Flow

Service monitor subscribes to IF-MAP server to get notification of configuration changes, the creation of service instance. Then it will connect to Contrail configuration API server and OpenStack Nova API server to create required components and launch service instance.

### 3.2 Relations

Service monitor depends on the following services.
* IF-MAP server
* Zookeeper
* Contrail configuration API server
* OpenStack Nova API server

