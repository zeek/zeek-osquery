# Docker #
This README explains how to setup two docker containers, for Bro and Osquery.

# Installing Bro #
*Stand by for updates*

# Installing osquery #
Download the `Dockerfile` within this install folder. Use your shell and go to the folder you saved the `Dockerfile` and run:

	docker build -t bro/bro-osquery:1.0.0 -t bro/bro-osquery:latest .
	
Afterwards, you need to configure the bro-osquery extension. Most importantly, you have to set the IP address of the bro instance you want to connect to:
	
	docker run -it --name bro-osquery bro/bro-osquery:latest /bin/bash
	vim /etc/osquery/osquery.conf
	
Finally, run osquery and the bro-osquery extension

	./run.sh
	
