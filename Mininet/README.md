This folder is used to test the firewall on custom topologies to examine performance. <br>
First, the mininet topology python script is to be run, followed by running xterm on hosts wished to be tested. <br>
After making sure the correct interface is used in the script.py file, we can run the script. <br>
With rules like only allowing a particular host, speed can be compared with the eBPF firewall against similar rules by eBPF or TC implementation. <br>
This can be done using iperf commands to set the server at the receiver node and the iperf client at the other.
