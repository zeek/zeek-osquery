# Install Summary #
This folder initially contains this README, a set of install (bash-)scripts per platform and a run script. Currently we only provide a script for Ubuntu 16.04. This might work also on other platforms.

Such an install script aims to encompass all steps required to finally run `bro-osquery`. The script itself is sufficient and does not require to be executed within the project structure as it will download all components, including the `bro-osquery` repository.

This procedure requires some tools to be intalled:  
	
	apt-get install sudo git cmake clang libcurl4-openssl-dev

Then execute the install script as a sudo user:  

	git clone https://github.com/bro/bro-osquery  
	cd bro-osquery  
	cd install && ./install_ubuntu_16_04.sh  

Afterwards, you can run `osquery` and the `bro-osquery` extension:

	./run.sh
		

## Component Setup ##
From a build system point of view, `bro-osquery` depends on two independent project, namely `osquery` as the host-monitor and `broker` as the communication part to bro. 

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;bro-osquery  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;------------------------------  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|  
libosquery&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;libbroker  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;libcaf  

`Osquery`, and as a result also the corresponding library, is built with a very specific tool chain that is nearly independent from the actual system environment. Almost all dependencies for the `osquery` project (including compiler, system libraries) are provided by brew.

To avoid build conflicts when including/linking against `osquery`, `bro-osquery` and as a consequence also `lilbbroker`+`libcaf` have to follow the very same tool-chain given by `osquery`. Next, we briefly describe what the install script does to achieve this.

The script will download all components directly to this folder, apply patches, compile and install them. The patches mainly ensure that all projects are compiled with:

	* -std=c++11
	* -stdlib=libstdc++
	* Several system libraries in `/usr/local/osquery`

### Osquery ###
First, osquery source is downloaded from [Github](https://github.com/facebook/osquery). After patching, we run `make deps` such that all dependencies are placed into `/usr/local/osquery`. Also, we run regular `make && make install` to install `libosquery` to `/usr/local`.

### Actor Framework ###
CAF sources are downloaded from [Github](https://github.com/actor-framework/actor-framework). We checkout release tag 0.14.5 as this is the latest version suitable for broker. After patching, we compile it with the corresponding tool-chain and install to `/usr/local`.

### Broker ###
Broker sources are downloaded from [Github](https://github.com/bro/broker). After patching, we compile it with the corresponding tool-chain and install to `/usr/local`.

### Bro-osquery ###
The interesting part happens for the integration of `bro-osquery`. These project sources are placed as a subdirectory into the CMake build system of  `osquery`. Therefore, a second iteration of patches to `osquery` will:

* Create the folder `./osquery/osquery/external/`
* Will modify the CMake file to include all projects in this *external* directory as potential [extensions](https://osquery.readthedocs.io/en/stable/development/osquery-sdk/#extensions). This functionality was introduced by this [commit](https://github.com/facebook/osquery/pull/2385). 

For convenience, we download the complete `bro-osquery` project from [Github](https://github.com/bro/bro-osquery/tree/dev/haas) and save it as  `./osquery/osquery/external/extension_bro_osquery`. The folder contains a CMake file that is not meant to be invoked standalone but during the build process of `osquery`.

Therefore, we now build `osquery` a second time. This time, it includes the `extension_bro_osquery` folder and compiles `bro-osquery` as an *extension*.



## Running Bro-Osquery ##
At the end of the install script, there are some hints on how to run `bro-osquery`. You can also use the run script that:

* Starts the osquery daemon with the appropriate parameters
* Starts bro-osquery as extension
