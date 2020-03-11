# The Zeek-Osquery Project #
This project adds a Zeek interface to the host monitor [osquery](https://osquery.io), enabling the network monitor [Zeek](https://www.zeek.org) (formerly known as Bro) to subscribe to changes from hosts as a continous stream of events. The platform is controlled by Zeek scripts, which sends SQL-style queries to the hosts and then begin listening for any updates coming back. Host events are handled by Zeek scripts the same way as network events.

Here, you see an example script to be loaded by Zeek, using osquery and our zeek-osuqery framework to make hosts report about server applications as soon as it starts.
```
event host_server_apps(resultInfo: osquery::ResultInfo,
	        username: string, name: string, port_number: int)
{
  print fmt("[Host %s] User '%s' is running server application '%s' on port %d", 
             resultInfo$host, username, name, port_number);
}

event bro_init()
{
  local query = [$ev=host_server_apps, 
                 $query="SELECT u.username, p.name, l.port from listening_ports l, users u, processes p 
                         WHERE l.pid=p.pid AND p.uid=u.uid and l.address NOT IN ('127.0.0.1', '::1')"];
  osquery::subscribe(query);
}
```

## Overview ##
Zeek-Osquery is a platform for infrastructure monitoring, combining network and host monitoring. Zeek is used to capture, log and analyze network packets. To retrieve information of hosts in the network, there is the osquery agent running on hosts. Osquery can be instrumented by Zeek to send information about software and hardware changes.

Both types of events, from network and hosts, are transparently handled with Zeek scripts. We provide an easy to use interface in Zeek to manage groups of hosts and to subscribe to host status changes.

## Installation ##
For the Zeek-Osquery Project to run, you need to deploy **Osquery** on respective hosts to be monitored. Additionally, **Zeek** has to be loaded with the **osquery framework script** to enable the communication with the hosts.

**Zeek** needs to be installed from source to include development features required by zeek-osquery.
Then, the **Zeek Script Framework** needs to be installed.

**Osquery** is originally a standalone host monitor and does not include the Zeek plugins yet. Hence, zeek-osquery cannot currently be used with the official osquery binaries. Use our customized osquery instead.

For detailed installation instructions please refer to the [installation guide](https://github.com/zeek/zeek-osquery/blob/master/install_guide.md).

## Deployment ##

Once you installed Zeek and placed the osquery framework, start Zeek with the scripts, e.g.:

	bro -i <interface_name> osquery

or run Zeek in background (after enabling the osquery framework):

    broctl deploy


Once you installed the zeek-featured osquery, you can start daemon and the zeek plugins:

	sudo osqueryd --disable-distributed=false --distributed_interval=0 --distributed_plugin bro --bro-ip="<bro-ip>" --logger_plugin bro --log_result_events=0

Please make sure that the *bro-ip* matches the Zeek installation running the osquery framework.

Additional command line flags in osquery that might be useful when running zeek-osquery:

      --verbose                Verbose osquery output
      --config_plugin update   Initial config from commandline only
      --disable_events=0       Enable event-based tables
      --disable_audit=0        Enable audit as event publisher (make sure auditd is not running)
      --audit_persist=1        Persistently controllig audit while running
      --audit_allow_config=1   More power to control audit
      --audit_allow_sockets=1  Include socket-related syscalls in audit

Osquery related logfiles are written to the Zeek log directory. Depending on the enabled osquery scripts, you should be able to see Zeek logfiles named osq-processes.log and osq-mounts.log.

## Known Issues ##

- When running Zeek in cluster mode, the manager already accepts incoming osquery connections via Broker, even though the custer did not build up completely, i.e., not all workers established Broker connections to the manager yet. When restarting the Zeek cluster and osquery hosts immediately reconnect, then state about hosts that reconnected before all workers reconnected is lost. Affected osquery hosts have to restart.

- Independent from the previous issue, Zeek (i.e. the manager) sometimes retrieves no state about some osquery hosts when restarting Zeek. This is not deterministic w.r.t. all restarts and all osquery hosts. When happening, it seems that Zeek never received the `new_host` announce message from osquery. Affected osquery hosts have to restart.

## Publications ##

Zeek-osquery initially started as an academic prototype to gain fundamental experiences in correlating host and network data for advanced monitoring and intrusion detection. Based on this work, the successor [zeek-agent](https://github.com/zeek/zeek-agent) is developed. Our results and experiences with zeek-osquery will be presented at the _35th International Conference on ICT Systems Security and Privacy Protection_ (IFIP SEC 2020). If you refer to our project, please cite our paper:

```
Steffen Haas, Robin Sommer, Mathias Fischer: zeek-osquery: Host-Network Correlation for Advanced Monitoring and Intrusion Detection. Accepted for publication at 35th International Conference on ICT Systems Security and Privacy Protection (IFIP SEC '20), Maribor, Slovenia, May 2020.
```
