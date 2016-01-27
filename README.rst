
Osquery-Extension for Bro
=========================

This extension adds a Bro interface to `osquery
<https://osquery.io>`_, enabling `Bro <https://www.bro.org>`_ to
subscribe to changes from hosts as a continous stream of events that
conceptually resemble the events that Bro generates from network
traffic. The extension is controlled from Bro scripts, which sends
SQL-style queries to the hosts and then begins listening for any
updates coming back.

Right now, we provide three pre-written Bro scripts that use this
extension to add the following events to::

    # Triggered for new processes on host.
    event osquery::processes(host: string, utype: string, pid: int,
                             path: string, cmdline: string, uid: int
                             gid: int, euid: int, egid: int, parent: int);


    # Triggered for new sockets opening up on host.
    event osquery:process_open_sockets(host: string, utype: string, pid:int,
                                       protocol: int, local_address: string,
                                       remote_address: string, local_port: int,
                                       remote_port: int)

    # Triggered for new USB devices
    event osquery::usb_devices(host: string, utype: string,
                               vendor: string, model: string,
                               serial: string, removable: int);

These events can be handled inside custom scripts like any other Bro
event. The pre-written scripts also record this host information into
corresponding Bro log files. Here's an excerpt from 
``osq-process.log``::

    #fields t               host            pid     ppid    path            uid     euid    gid     egid    argv
    #types  time            string          int     int     string          int     int     int     int     string
    1453849601.880629       127.0.0.1       40136   40125   /usr/bin/git    10000   10000   10000   10000   git diff --no-ext-diff --quiet --exit-code
    1453849643.924678       127.0.0.1       40397   1485    /usr/bin/git    10000   10000   10000   10000   git push
    1453849643.924678       127.0.0.1       40404   40398   /usr/bin/ssh    10000   10000   10000   10000   ssh git@github.com git-receive-pack '/bro-osquery'

.. note::

    This extension is in still early prototype state. We're actively
    working on it and appreciate any feedback.

    We have so far tested it on CentOS7 and Fedora 22 Linux systems.
    We plan to port it to FreeBSD soon.


Installation
------------

We recommend to start by building all of osquery, Bro, and the
extension on the same host, which we call the "build host" in the 
following. We also assume that Bro will then run on that system. For
the host systems to be monitored with osquery ("end systems"), the
installation footprint is smaller and best done through packages that
install just the binary versions of osquery and extensions.

Build Host
~~~~~~~~~~

Due to the number of pieces involved, the installation is a bit more
complex and might differ in specifics depending on the platform.
Generally, the following are the main steps to (1) install osquery
into ``/usr/local``; (2) install the bro-osquery extension with its
dependencies into ``/opt/bro-osquery``; and (3) install Bro into
``/opt/bro/``. This is all best done as root, as multiple parts need
corresponding permissions. We generally require recent development
versions of all the software right now.

    - Build and install `osquery <https://osquery.io>`_::

        # git clone http://github.com/facebook/osquery.git
        # cd osquery
        # make deps && make && make install
        # mkdir /var/osquery && cp /usr/local/share/osquery/osquery.example.conf /var/osquery/osquery.conf

      Check ``osquery.conf`` if you need to edit anything.

    - Build and install `CAF <https://github.com/actor-framework/actor-framework>`_
      (a dependency for Bro's communication library Broker)::

        # git clone https://github.com/actor-framework/actor-framework
        # cd actor-framework
        # ./configure --prefix=/opt/bro-osquery
        # make && make install

    - Build and install `Broker <https://www.bro.org/sphinx/components/broker/broker-manual.html>`_::

        # git clone git://git.bro.org/broker
        # cd broker
        # ./configure --prefix=/opt/bro-osquery
        # make && make install

    - Build and install `Bro <https://www.bro.org>`_::

        # git clone --recursive git://git.bro.org/bro
        # cd bro
        # ./configure --prefix=/opt/bro --with-libcaf=/opt/bro-osquery
        # make && make install

    - Build and install the bro-osquery plugin::

        # git clone git://git.bro.org/bro-osquery
        # ./configure --prefix=/opt/bro-osquery --with-bro=/opt/bro
        # make && make install

      .. note:: You need to install the plugin as root, as osqery
         requires it to be owned by root (and doesn't report an error
         if it isn't; it just won't use it).

    - Edit ``/opt/bro-osquery/etc/broker.ini``: Fill in ``HostName``
      and ``master_ip``. For now you have to use *IP addresses*, not
      hostnames, in either case. This fill be fixed later.

    - Edit the Bro configuration:

        - Add ``@load osquery`` to
          ``/opt/bro/share/bro/site/local.bro``.

        - If you want to monitor network traffic in parallel, set the
          ``interface`` in ``/opt/bro/etc/node.cfg``. If not, remove
          the ``interface`` from ``/opt/bro/etc/node.cfg`` and add
          ``redef exit_only_after_terminate=T`` to ``local.bro``.

        - Run ``/opt/bro/bin/broctl install``, then
          ``/opt/bro/bin/broctl check``.

    - Start Bro with ``/opt/bro/bin/broctl start``. Bro logs will be
      written to ``/opt/bro/logs/current``.

    - To monitor host activity on the build host, start ``osqueryd``
      with ``/usr/local/bin/osqueryd
      --extensions_autoload=/opt/bro-osquery/etc/osquery/bro.load``

      ``/opt/bro/logs/current/osquery.log`` will record incoming
      connections from the extension, and
      ``/opt/bro/logs/current/osq-*.log`` will record reported
      activity.

End Systems
~~~~~~~~~~~

TODO: Figure out steps for building packages.


Todo List
---------

This is early code that still needs quite a bit of work. Missing
pieces include:

    - Add support for communicating over SSL (needs SSL support in
      Broker).

    - Switch to osquery's event-based interface where possible,
      instead of polling for changes (which misses stuff)

    - Port to FreeBSD and OS X.

    - Quieten the extension's debug output.

    - Avoid having to put the local IP address into ``HostName``
      (needs CAF and Broker updates).

    - Clean up the code base and improve stability.


