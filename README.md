# The Bro-Osquery Project#
This extension adds a Bro interface to the host monitor [osquery](https://osquery.io), enabling the network monitor [Bro](https://www.bro.org) to subscribe to changes from hosts as a continous stream of events. The extension is controlled from Bro scripts, which sends SQL-style queries to the hosts and then begins listening for any updates coming back. Host events are handled by Bro scripts the same way as network events.

## Overview ##
Bro-Osquery is a platform for infrastructure monitoring, combining network and host monitoring. Bro is used to capture, log and analyze network packets. To retrieve information of hosts in the network, there is the osquery agent running on hosts. Osquery can be instrumented by Bro to send information about software and hardware changes.

Both types of events, from network and hosts, are transparently handled with Bro scripts. We provide an easy to use interface in Bro to manage groups of hosts and to subscribe to host status changes.

## Installation ##
For the Bro-Osquery Project to run, you need to deploy osquery on respective hosts to be monitored. Additionally, Bro has to be loaded with the osquery framework script to enable the communication with the hosts.

**Bro-Scripts** can be found in this Github repository. The osquery folder contains the script framework. Please load it in your Bro installation. Once you placed the osquery framework, start Bro with the scripts, e.g.:

	bro -i eth0 site/osquery

**Osquery** is originally a standalone host monitor. We are currently integrating our project into osquery. The latest version of this integration branch is also available as a [Github repository](https://github.com/iBigQ/osquery/tree/bro_integration). While we are working on integration, you can check out this version.

	git clone https://github.com/iBigQ/osquery.git
	checkout -b bro_integration
	make deps && make
	sudo make install
	
After installation, you can start the osquery daemon and the bro extension:

	sudo osqueryd --verbose --logger_plugin bro --config_plugin filesystem --allow_unsafe --log_result_events=0 --disable-bro=false --bro-ip="172.17.0.2"

Please make sure that the *bro-ip* matches the Bro installation running the osquery framework.

As an example, you should be able to see Bro logfiles named osq-processes.log and osq-mounts.log.