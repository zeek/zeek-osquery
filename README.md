# Branch Info #
This is a development branch of `bro-osquery`that aims for creating additional report capabilities of the `osquery` host sensor. Using the network security monitor `Bro` and its communication library `broker`, we make `osquery` to receive SQL subscription from `Bro` and to return events occuring on the monitored host matching the SQL query.

## Architecture ##
We design this solution according to some requirements:

* We want these report capabilities with few osquery changes as possible. Also, users should be able to use bro-osquery without having to re-compile osquery or bro-osquery on their own.

Therefore, this branch is development bro-osquery with characteristics as follows:

1. **Writing bro-osquery mainly as extension**
    * Having our solution implemented as an osquery extension, we can distribute this binary to any user that wants to extend an existing osquery installation.
    * As we want Bro to be able to push new SQL queries to osquery at any time, we need to permanently listen on the broker endpoint for new incoming messages. The config-plugin can [retrieve](https://github.com/facebook/osquery/blob/master/include/osquery/config.h#L368) the config only once at startup. Alternatively to an extension, we could also implement this functionaly similar to the [distributed-plugin](https://github.com/facebook/osquery/blob/master/osquery/main/posix/daemon.cpp#L36). We might consider this as future work.
   
2. **Using the osquery scheduler**
    * Bro-osquery will (mainly) not actively schedule and execute the SQL queries. Instead, it maintains all queries requested by any Bro to update the interal osquery schedule with new queries.
    * For this reason, the extension directly updates the schedule/config of osquery directly without the need for any config-plugin. Hence, config-plugin should be disabled by the run flag `--config_plugin update`.
   
3. **Using LoggerPluging**
    * Osquery calls the logger-plugin to log the results of a query, (including/exclusively?) the [results of scheduled queries](https://github.com/facebook/osquery/blob/master/osquery/dispatcher/scheduler.cpp#L79). The logger-plugin sends each result row as an event back to the respective bro.
    * A result row can be mapped to a specific SQL schedule query, and the respective Bro that subscribed to this query.
    * To be able to parse the serialized log string, the run flag `--log_result_events=0` must be set.
 
4. **Using one Broker Endpoint**
     * Extension (receiving new queries from Bros) and logger-plugin (sending out query results) run in the same process, so we can easily share the same broker endpoint for these reasons.
     
5. **Handling Osquery Events**
    * The logger-plugin currently receives also results from the event-tables according to the regular schedule.
    * TODO: 
        * The logger-plugin can also request to be directly invoked when an [event](https://github.com/facebook/osquery/blob/master/osquery/logger/logger.cpp#L421) occurs.
        * This seems to be independent from the scheduled queries. Hence, we would have to manually match such reported events against the queries we received from bro

 
## Installation ##
 As this branch is under heavy development, we currently also work on a build system to integrate `bro-osquery` into `osquery`. There is no working solution for all platforms yet. However, here are some implications when compiling `bro-osquery`:
 
 1. Osquery comes with its own dependencies, system libraries and compilers (delivered with brew). As a result, also the library `libosquery` is build with this custom tool-chain.
 2. When building bro-osquery and including/linking against `libosquery`, we need the very same tool-chain. That is why we will integrate bro-osquery into the build system of osquery.
 3. Also the libraries `libbroker` and `libcaf` need to be built following the same tool-chain to avoid conflicts. In particular, this includes:
     * -std=c++11
     * -stdlib=libstdc++
     * Several system libraries in `/usr/local/osquery`
     
Once the build process is stable, we will release an install script.

## Deployment ##
The config file (i.e. `/etc/osquery/osquery.conf`) was extended by another key named `bro`. The setting `bro_endpoint` must be set such that:

    {
    // Configure the daemon below:
      "bro": {
        // Address of bro
        "bro_endpoint": "172.17.0.2:9999"
      },
    
      "options": {
        ...
