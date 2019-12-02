# Installation Guide #

## 1. Osquery

### Compile Osquery

The most recent osquery development required for zeek-osquery is currently located in the [osquery fork by iBigQ](https://github.com/iBigQ/osquery). It is based on osquery version 3.3.0 and is upgraded to the latest osquery version when possible.

```
git clone --recursive https://github.com/iBigQ/osquery
cd osquery
make deps
./tools/provision.sh install osquery/osquery-local/caf
./tools/provision.sh install osquery/osquery-local/broker
SKIP_BRO=False make && sudo make install
```

This installation includes the latest development version of the communication library Broker that comes with e.g. SSL support.

### Init Service
Optionally, please see the official [osquery documentation](http://http://osquery.readthedocs.io/en/stable/installation/install-linux/#running-osquery) on how to install osquery daemon as a service.

### Configuration File
You can specify the configuration options required for zeek-osquery either on the command line or in the configuration file of osquery. Optionally, please see the official [osquery documentation](http://osquery.readthedocs.io/en/stable/deployment/configuration/#configuration-components) on how to write the configuration file. Possible options are as follows:

```json
{
  "options": {
    "disable_distributed": "false",
    "distributed_interval": "0",
    "distributed_plugin": "bro",

    "bro_ip": "192.168.137.1",
    "bro_port": "9999",

    "bro_groups": {
        "group1": "geo/de/hamburg",
        "group2": "orga/uhh/cs/iss"
    },

    "logger_plugin": "bro",
    "log_result_events": "false",

    "disable_events": "0",
    "disable_audit": "0",
    "audit_persist": "1",
    "audit_allow_config": "1",
    "audit_allow_sockets": "1"
  }
}
```

## 2. Zeek

### Compile Zeek and Dependencies

Build Zeek version 2.6.4 from source to include a particular Broker version.

```
git clone --recursive https://github.com/zeek/zeek --branch v2.6.4
cd zeek
./configure && make && sudo make install
```

### Osquery Framework

The Zeek scripts have to be extended to be able to talk to osquery hosts. Please find the scripts in the [zeek-osquery repository](https://github.com/zeek/zeek-osquery) repository in the folder named `osquery`.
To make the scripts available in Zeek, either copy/link this folder into *$PREFIX/share/bro/site* (see [Zeek manual](https://www.zeek.org/sphinx/quickstart/index.html#zeek-scripts)) or make the environment variable BROPATH to point to the framework folder (see [Zeek manual](https://www.zeek.org/sphinx/quickstart/index.html#telling-zeek-which-scripts-to-load)).
Alternatively, use the bro package manager and configure the custom package source `https://github.com/ibigq/zeek-osquery-packages` to install the respective zeek-osquery packages.
