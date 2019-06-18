==================================================================
muddy: IETF MUD file validator
==================================================================

source available at - <insert Github link>
installer available at - <insert SDIST link>

Installer dependencies
----------------------

netaddr==0.7.10,
mako==0.8,
ipaddr==2.1.11

Pre-requisites
---------------

1. MGtoolkit 1.0.16 must be installed on the local system. This can be done using the .gz file provided, by entering

    $ sudo pip install mgtoolkit-1.0.16.tar.gz       // MAC-OSX

    $ pip install mgtoolkit-1.0.16.tar.gz            // Linux


Installation on MAC-OSx
----------------

to install muddy python package from .tar.gz:

$ sudo pip install muddy-0.11.tar.gz

this will automatically check and install any dependencies missing on local system



Installation on Linux
---------------------

$ sudo apt-get install python-pip
$ pip install muddy-0.11.tar.gz

this will automatically check and install any dependencies missing on local system


Feature use
----------------------------

1. Generate MUD files for common flows:

        $ muddy --createmud <full path and name of folder containing flow rule .csv files>

        Informs the if invalid flows are detected, creates MUD file per .csv file.

2. Check consistency of generated MUD files

        $ muddy --checkmud <full path and name of the 'results' folder containing MUD (.json) files>

        Informs the user of any intent-ambiguous rules (ie overlapping rules with different outcomes)
        and redundancies (ie duplicate rules and other ovelapping rules with same outcome)


3. Compare the created MUD files against a high-level SCADA best practice policy

    $ muddy --bpcompare <full path and name of MUD file>

    Informs the user whether the MUD policy is best practices compliant or not. If so, it will list zones within a SCADA network
    where the device can be installed.
