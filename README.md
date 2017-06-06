# The Bro-Osquery Project#
This extension adds a Bro interface to the host monitor [osquery](https://osquery.io), enabling the network monitor [Bro](https://www.bro.org) to subscribe to changes from hosts as a continous stream of events. The extension is controlled from Bro scripts, which sends SQL-style queries to the hosts and then begins listening for any updates coming back. Host events are handled by Bro scripts the same way as network events.

Here, you see an example script to be loaded by Bro, using osquery and our bro-osuqery framework to make hosts report about server applications as soon as it starts.
```
event host_server_apps(resultInfo: osquery::ResultInfo,
	        username: string, name: string, port_number: int)
	{
	print fmt("[Host %s] User '%s' is running server application '%s' on port %d", resultInfo$host, username, name, port_number);
	}

event bro_init()
	{
	Broker::enable();

	local query = [$ev=host_server_apps, $query="SELECT u.username, p.name, l.port from listening_ports l, users u, processes p WHERE l.pid=p.pid AND p.uid=u.uid and l.address NOT IN ('127.0.0.1', '::1')"];
	osquery::subscribe(query);
	}
```

## Overview ##
Bro-Osquery is a platform for infrastructure monitoring, combining network and host monitoring. Bro is used to capture, log and analyze network packets. To retrieve information of hosts in the network, there is the osquery agent running on hosts. Osquery can be instrumented by Bro to send information about software and hardware changes.

Both types of events, from network and hosts, are transparently handled with Bro scripts. We provide an easy to use interface in Bro to manage groups of hosts and to subscribe to host status changes.

## Installation ##
For the Bro-Osquery Project to run, you need to deploy **Osquery** on respective hosts to be monitored. Additionally, **Bro** has to be loaded with the **osquery framework script** to enable the communication with the hosts.

**Bro** needs to be installed from source, because the binary packages do not include the broker communication library. Please install the [caf library](https://github.com/actor-framework/actor-framework/) version 0.14.6 and the [broker library](https://github.com/bro/broker/) version 0.6. Then follow the instructions on [Bro.org](https://www.bro.org/sphinx/install/install.html) and include broker using `./configure --enable-broker`. 

Now add the **Bro Script Framework** to your bro installation. It can be found in this Github repository at path [bro/osquery](https://github.com/bro/bro-osquery/tree/master/bro/osquery). To make the scripts available in Bro, either copy/link this folder into *$PREFIX/share/bro/site* (see [Bro manual](https://www.bro.org/sphinx/quickstart/index.html#bro-scripts)) or make the environment variable BROPATH to point to the framework folder (see [Bro manual](https://www.bro.org/sphinx/quickstart/index.html#telling-bro-which-scripts-to-load)). Once you placed the osquery framework, start Bro with the scripts, e.g.:

	bro -i eth0 osquery

**Osquery** is originally a standalone host monitor. We are currently integrating our project into the osquery code. This enables osquery to communicate with bro without any additional modifications. The latest version of this integration branch is also available as a [Github repository](https://github.com/iBigQ/osquery/tree/bro_integration). While we are working on integration, you can check out this development version.

	git clone https://github.com/iBigQ/osquery.git
	cd osquery && git checkout bro_integration
	make deps && make
	sudo make install
	
After installation, you can start the osquery daemon and the bro extension:

	sudo osqueryd --verbose --disable-distributed=false --distributed_interval=0 --distributed_plugin bro --bro-ip="172.17.0.2" --logger_plugin bro --log_result_events=0 --config_plugin update

Please make sure that the *bro-ip* matches the Bro installation running the osquery framework.

As an example, you should be able to see Bro logfiles named osq-processes.log and osq-mounts.log.