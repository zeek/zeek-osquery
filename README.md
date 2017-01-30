# Project Info #
This extension adds a Bro interface to the host monitor [osquery](https://osquery.io), enabling the network monitor [Bro](https://www.bro.org) to subscribe to changes from hosts as a continous stream of events. The extension is controlled from Bro scripts, which sends SQL-style queries to the hosts and then begins listening for any updates coming back. Host events are handled by Bro scripts the same way as network events.

## Architecture ##
We designed this architecture according to some requirements:

* We want these report capabilities with few osquery changes as possible. Also, users should be able to use bro-osquery without having to re-compile osquery or bro-osquery on their own.

Therefore, bro-osquery is developed with characteristics as follows:

1. **Writing bro-osquery mainly as extension**
    * Having our solution implemented as an osquery extension, we can distribute this binary to any user that wants to extend an existing osquery installation.
    * As we want Bro to be able to push new SQL queries to osquery at any time, we need to permanently listen on the broker endpoint for new incoming messages. The config-plugin can [retrieve](https://github.com/facebook/osquery/blob/master/include/osquery/config.h#L368) the config only once at startup. Alternatively to an extension, we could also implement this functionaly similar to the [distributed-plugin](https://github.com/facebook/osquery/blob/master/osquery/main/posix/daemon.cpp#L36). We might consider this as future work.
   
2. **Using the osquery scheduler**
    * Bro-osquery will (mainly) not actively schedule and execute the SQL queries. Instead, it maintains all queries requested by any Bro to update the interal osquery schedule with new queries.
    * For this reason, the extension directly updates the schedule/config of osquery directly without the need for any config-plugin. However, we made the extension configuration part of the regular config. Hence, config-plugin should be set to retrieve an initial configuration (e.g. `--config_plugin filesystem`).
   
3. **Using LoggerPluging**
    * Osquery calls the logger-plugin to log the [results of scheduled queries](https://github.com/facebook/osquery/blob/master/osquery/dispatcher/scheduler.cpp#L79). The logger-plugin sends each result row as an event back to the respective bro.
    * A result (row) can be mapped to a specific SQL schedule query, and the respective Bro that subscribed to this query. Furthermore, this allows to parse the result values and convert them to datatypes according to the query.
    * To be able to parse the serialized log string, the run flag `--log_result_events=0` must be set.
 
4. **Using one Broker Endpoint**
     * Extension (receiving new queries from Bros) and logger-plugin (sending out query results) run in the same process, so we can easily share the same broker endpoint for these reasons.
     
5. **Handling Osquery Events**
    * The logger-plugin currently receives also results from the event-tables according to the regular schedule.
    * TODO: 
        * The logger-plugin can also request to be directly invoked when an [event](https://github.com/facebook/osquery/blob/master/osquery/logger/logger.cpp#L421) occurs.
        * This seems to be independent from the scheduled queries. Hence, we would have to manually match such reported events against the queries we received from bro

 
## Installation ##
 As this project is under heavy development, we currently also work on a build system to integrate `bro-osquery` into `osquery`. There is no working solution for all platforms yet. However, here are some implications when compiling `bro-osquery`:
 
 1. Osquery comes with its own dependencies, system libraries and compilers (delivered with brew). As a result, also the library `libosquery` is build with this custom tool-chain.
 2. When building bro-osquery and including/linking against `libosquery`, we need the very same tool-chain. That is why we will integrate bro-osquery into the build system of osquery.
 3. Also the libraries `libbroker` and `libcaf` need to be built following the same tool-chain to avoid conflicts. In particular, this includes:
     * -std=c++11
     * -stdlib=libstdc++
     * Several system libraries in `/usr/local/osquery`
     
We are working on a stable build process an release an install script as soon as possible.

## Deployment ##
After installation, the config file (i.e. `/etc/osquery/osquery.conf`) needs to be modified. Running the bro-osquery extension requires to retrieve at least the IP address of the Bro instanace it connects to. Therefore, the configuration was extended by the key named `bro`. The setting `bro_ip` must be set such that:

    {
      "bro": {
        // Address of bro
        "bro_ip": "172.17.0.2"
      },
    
      "options": {
        "logger_plugin": "bro"
      }
    }

To run bro-osquery, start the osquery deamon along with the extension. Load the osquery framework scripts in Bro to schedule queries. 