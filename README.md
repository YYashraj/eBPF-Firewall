# eBPF-Firewall
Instructions to run main programs-
<pre>
	The python scripts can be run by the following command: sudo python3 &lt;python_file_name&gt;
	Most of the C code does not need to be run separately; The related python script will compile it.
	To replay the pcap file: sudo tcpreplay -v --mbps &lt;speed> -i &lt;interface_name> 1.pcap 
</pre>
The folder 'IP and Port Filter' has the final code for our filter implementation

# TC - Linux Traffic Control
Instructions and commands to run TC programs and check the outputs. 

## Traffic Shaping

# ipRules Commands Sheet
<pre>
''' IP related commands '''

Rules block I IP &lt;ip_address> : blocks incoming traffic from source IP = &lt;ip_address>
Rules block O IP &lt;ip_address> : blocks outgoing traffic for destination IP = &lt;ip_address>
Rules block IP &lt;ip_address>   : blocks incoming and outgoing from IP = &lt;ip_address>

Rules unblock I IP &lt;ip_address> : if the specified IP is blocked then re-allows incoming traffic from source IP = &lt;ip_address>, else displays a custom message
Rules unblock O IP &lt;ip_address> : if the specified IP is blocked then re-allows outgoing traffic to destination IP = &lt;ip_address>, else displays a custom message
Rules unblock IP &lt;ip_address>   : performs the above two commands

Rules unblock I IP all : Clears out "Blocked Incoming IPs" map; No incoming packet is restricted
Rules unblock O IP all : Clears out "Blocked Outgoing IPs" map; No outgoing packet is restricted
Rules unblock IP all   : Removes any IP-based filteration implemented (A pop-up for confirmation will appear. Enter Y to proceed and N to abort.

''' Port related commands '''

Rules block sp &lt;Port>   : blocks all data over the network from source port = &lt;Port>
Rules block dp &lt;Port>   : blocks all data over the network to destination port = &lt;Port>
Rules block u sp &lt;Port> : blocks data to main host from source port = &lt;Port>
Rules block u dp &lt;Port> : blocks data from main host to destination port = &lt;Port>

Rules unblock sp &lt;Port>   : if blocked, re-allows data reception from source port = &lt;Port> over the network
Rules unblock dp &lt;Port>   : if blocked, re-allows data transmission to destination port = &lt;Port> over the network
Rules unblock u sp &lt;Port> : if blocked, re-allows data reception from source port = &lt;Port> for main host
Rules unblock u dp &lt;Port> : if blocked, re-allows data transmission to destination port = &lt;Port> for main host

''' Utility commands '''

show Rules   : displays the contents of the latest saved version of Rules.txt
show update  : displays the unsaved version of Rules.txt after all the commands passed in the current session
update Rules : saves the changes in Rules.txt
undo changes : reverts back to last saved version of Rules.txt, nullifying all later unsaved updates
exit         : Closes ipRules
</pre>
