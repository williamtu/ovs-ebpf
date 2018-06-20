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

======================
Open vSwitch with BPF
======================

This document describes how to build and install Open vSwitch using an BPF
datapath.

.. warning::
  The BPF support of Open vSwitch is considered 'experimental'.

Build requirements
------------------

In addition to the requirements described in :doc:`general`, building Open
vSwitch with DPDK will require the following:

- LLVM 3.7.1 or later

- Clang 3.7.1 or later

- iproute-dev 4.6 or later

- Linux kernel 4.10 or later

  The following Kconfig options must be enabled to run the BPF datapath:

``_CONFIG_BPF=y``
``_CONFIG_BPF_SYSCALL=y``
``_CONFIG_NET_CLS_BPF=m``
``_CONFIG_NET_ACT_BPF=m``

  The following optional Kconfig options are also recommended:

``_CONFIG_BPF_JIT=y``
``_CONFIG_HAVE_BPF_JIT=y``

- Linux-tools from a recent Linux kernel

Installing
----------

OVS can be installed using different methods. For OVS to use BPF datapath, it
has to be configured with BPF support (``--with-bpf``).

#. Clone a recent version of Linux net-next tree::

   $ git clone git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git

#. Go into the Linux source directory and build libbpf in the tools directory::

    $ cd linux/
    $ make -C tools/lib/bpf/

#. Ensure the standard OVS requirements, described in
   :ref:`general-build-reqs`, are installed

#. Bootstrap, if required, as described in :ref:`general-bootstrapping`

#. Configure the package using the ``--with-bpf`` flag::

       $ ./configure --with-bpf=$LINUX_TOOLS

   where ``LINUX_TOOLS`` is the path to the Linux tools/ directory that was
   compiled in step 2.

   .. note::
     While ``--with-bpf`` is required, you can pass any other configuration
     option described in :ref:`general-configuring`.

#. Build and install OVS, as described in :ref:`general-building`

Additional information can be found in :doc:`general`.

Setup
-----

Before running OVS, you must ensure that the BPF filesystem is available::

    # mount -t bpf none /sys/fs/bpf
    # mkdir -p /sys/fs/bpf/ovs

   .. note::
     We should get rid of this requirement on users, and just robustly ensure
     that the filesystem is available and prepared correctly (or do so if it
     is not).

Open vSwitch should be started as described in :doc:`general`.

   .. note::
     Depending on how OVS was installed, the BPF datapath binary may or may
     not be available. Check the logs when running OVS, if it complains about
     not finding bpf/datapath.o, look for this file in your OVS build tree and
     copy/symlink it across. Probably it's supposed to live in
     /usr/share/openvswitch/bpf/datapath.o.

If the linux-tools package is not installed with libbpf.so, then ensure
that this library is available via your library path::

    $ export LD_LIBRARY_PATH=${LINUX_TOOLS}/lib/bpf:$LD_LIBRARY_PATH

When adding a bridge to Open vSwitch, specify the datapath type as bpf::

    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=bpf

To validate that the bridge has successfully instantiated, you can use the
ovs-bpfctl utility::

    # ovs-bpfctl show

Limitations
------------

- The BPF datapath is a work in progress and has a limited set of support
  for matching and actions.

Bug Reporting
-------------

Please report problems to bugs@openvswitch.org.
