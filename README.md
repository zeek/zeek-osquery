## OSquery-Extension ##

This module has been tested with 
linux: CENTOS7 (3.10.0-229.11.1.el7.x86_64)

Note: actor framework version should be the same at both sides (bro and osquery side)


-------------------------------------------------------
###Step 1: Follow Osquery Extension Guidelines###
-------------------------------------------------------
We have developed osquery extension which will enable bro users to subscribe to 
SQL queries remotely at osquery daemons within a subnet and then get the queries updates till the
broker connection is alive. Once the SQL queries are received from bro then
extension will send an initial dump if the inidump flag is set to true;
otherwise, it will only monitor updates of events and send them to bro.
Bro user can subscribe and unsubscribe SQL queries at any time during execution.


Broker is a communication library which is used as a communication module 
between osquery extension and bro IDS.

####1.1 Pre-Installation requirements: ####

Here follows the list of libraries requied to build extension
- broker 
- boost_thread
- thrift
- rocksdb
- boost_system
- crypto
- glog
- boost_filesystem
- thriftz
- osquery

Broker link:
```git clone --recursive https://github.com/bro/broker```

The rest of libraries will be readily available with the working osquery install. Clone the latest osquery from here: 
https://github.com/facebook/osquery/ 

####1.2 Installation Steps: ####

* ```git clone https://github.com/sami2316/OSquery-Extension.git```
*	```cd OSquery-Extension```
*	```make```
*	```make install```

####1.3 Application usage guide:####
* Change master IP and update interval (default value is 250 msec) var/osquery/broker.ini
*	```osqueryd --extensions_autoload=/etc/osquery/extensions.load ```

-------------------------------------------------				
###Step 2: Follow Bro Extension Guideline###
-------------------------------------------------

We have added osquery query subscription module using broker functionality in 
bro IDS. This module is about subscribing SQL queries from bro (master) to 
osquery hosts and then receiving updates of subscribed events. 
Default subscription behavior is for update events only but you can request an 
initial dump by setting inidump flag to true during the subscription process. 

To use our osquery-module you need to first install bro. Here follows the installation guide:

####2.1 Installation steps:####
*	install actor-framework from github
*	```git clone --recursive https://github.com/bro/bro.git```
*	```./configure```
*	```make```
*	```make install```

Note: actor framework version should be the same at both sides (bro and 
       osquery side)

----------------------------------------------
###Step 3: Start Using Monitoring Application###
----------------------------------------------
At bro-master:
Add bro/osquery to your BROPATH and then just run
```bro osquery exit_only_after_terminate=T```

At osquery-hosts:
```osqueryd --extensions_autoload=/etc/osquery/extensions.load ```

Note: ```process.bro``` and ```sockets.bro``` has been added as an example scripts to log processes and open sockets
at any osquery host in the subnet.

You can write the similar bro-srcipts to monitor other events at osquery daemons. After writing new .bro scripts, just add them to ```__load__.bro```.
