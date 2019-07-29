..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.


========================
Open vSwitch with MEMIF
========================

This document describes how to build and install Open vSwitch using
MEMIF netdev.

.. warning::
  The MEMIF support of Open vSwitch is considered 'experimental',
  and it is not compiled in by default.


Introduction
------------
MEMIF is an interface for container networking,
see [1,2] for introduction and [3] for build.

[1] https://docs.fd.io/vpp/17.10/libmemif_doc.html
[2] https://www.youtube.com/watch?v=6aVr32WgY0Q
[3] https://docs.fd.io/vpp/17.10/libmemif_build_doc.html


Installing
----------
For OVS to use memif netdev, it has to be configured with libmemif support.
First, clone a recent version of VPP tree::

  git clone https://gerrit.fd.io/r/vpp

Second, go into the vpp source directory::

  cd vpp/extras/libmemif/
  mkdir build
  cd build
  cmake ..
  make

.. note::
   Make sure lib/libmemif.h is installed in system's library path,
   e.g. /usr/local/include/ or /usr/include/.
   And make sure build/lib/libmemif.so is copied to shared lib path.

Make sure the libmemif.so is installed correctly::

  ldconfig
  ldconfig -p | grep libmemif

Third, ensure the standard OVS requirements are installed and
bootstrap/configure the package::

  ./boot.sh && ./configure --enable-memif

Finally, build and install OVS::

  make && make install


Setup MEMIF netdev
-------------------
Open vSwitch should be started using userspace datapath as described
in :doc:`general`::

  ovs-vswitchd ...
  ovs-vsctl -- add-br br0 -- set Bridge br0 datapath_type=netdev
  ovs-vsctl add-port br0 memif0 -- set int memif0 type=memif
  ovs-vsctl add-port br0 memif1 -- set int memif1 type=memif

OVS memif0 and memif1 runs as master mode, install OpenFlow rules::

  ovs-ofctl add-flow br0 "in_port=memif0 actions=output:memif1"
  ovs-ofctl add-flow br0 "in_port=memif1 actions=drop"

To send packets to memif ports, I use the example program from vpp::

  cd extras/libmemif/build/examples
  ./icmp_responder-epoll
  LIBMEMIF EXAMPLE APP: ICMP_Responder (debug)
  ==============================
  libmemif version: 3.0

Connect to memif0 (slave) and memif1 (slave) and send 1000
packets to memif0::

  conn 0 0 0
  conn 1 0 0
  send 0 1000 192.168.1.100 aa:bb:ff:ee:11:22

Check the stats at OVS by doing::

  ovs-ofctl dump-flows br0
  <skip> table=0, n_packets=1000, n_bytes=42000, in_port=memif0 actions=output:memif1
  <skip> table=0, n_packets=1000, n_bytes=1024000, in_port=memif1 actions=drop


Bug Reporting
-------------

Please report problems to dev@openvswitch.org.
