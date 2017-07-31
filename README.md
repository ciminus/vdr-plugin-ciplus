# VDR CI+ Plugin

Written by: ciminus (ci.minus@protonmail.com)

This plug-in is a feasibility study of an implementation of the CI Plus standard for VDR.  
It largely implements the CI Plus Specification 1.2 but the plugin is not functional  
because it does not contain any certificates or other private data.

See the COPYING file for licence information.

## 1. Requirements ##

* VDR 2.3.5 or greater
* A VDR compatible DVB card with CI Slot or a standalone CI Adapter
* Openssl, zlib (and their devel packages)
* To disable parental rating promt of some CAMs, a Digital Devices CI with  
  VDR DDCI2 Plugin (V1.0.5 or higher) is required

## 2. Installation ##

* Install plugin:

    tar -xvf vdr-ciplus-<VERSION>.tgz  
    cd ciplus-<VERSION>  
    make  
    make install  

* If the plugin isn't able to get their parametes via pkgconfig:

    tar -xvf vdr-ciplus-<VERSION>.tgz  
    ln -s ciplus-<VERSION> [VDR-SOURCE-DIR]/PLUGINS/src/ciplus  
    cd [VDR-SOURCE-DIR]/PLUGINS/src/ciplus  
    make  
    make install

* To start the plugin with VDR, start vdr with the following parameter:

    -P ciplus  

## 3. Plugin parameter ##

The plugin has the following optional parameter:

* For debug output on stderr use the following parameter:

    -d  

* The plugin is able to load some private parts from an extra library (Not part of this plugin).  
  You can place the library in the VDR lib dir or load the library from a custom place  
  by using the following parameter:  

    -l [lib with private data]

* To switch the supported CI+ Specification, you can use the following parameter.
  Possible values are: 
   12 = CI+ V1.2
   13 = CI+ V1.3 (default)

    -v [CI+ Specification]


## Thanks to ##

* the original dreambox ciplus plugin developer
* j&k
