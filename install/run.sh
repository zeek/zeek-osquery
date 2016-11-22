#! /bin/bash

osquerydCMD="sudo osqueryd --verbose --extensions_autoload=extensions.load --extensions_timeout=3 --extensions_interval=3 --logger_plugin bro --config_plugin update --allow_unsafe --log_result_events=0"
echo "./osquery/build/linux/osquery/external/extension_bro_osquery/bro-osquery.ext" > extensions.load

echo "Executing: $osquerydCMD"
$($osquerydCMD)
