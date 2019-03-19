# Dns Fuzzer (cooler name will come later)

This is a DNS Fuzzer that I have made. It comes with crash detection and crash replay. To use it, first create a file called "records" in the same directory as the fuzzer with the dns records for the target in the following format:

```
<record type>,<record question>,<record class>
```

in general `<record question>` is the data that the query prompts with

Here are some examples:
```
$	cat records 
A,guy.tux.com,IN
AAAA,guy.tux.com,IN
SOA,tux.com,IN
MX,tux.com,IN
```

Here are the arguments:
```
$	sudo python fuzz.py -h
Initializing fuzzer
Help Menu: 
-i <ip> or --remote-ip <ip>		: Specify that <ip> is the IP address being fuzzed. Default 127.0.0.1
-p <port> or --remote-ip <port>		: Specify that <port> is the port being fuzzed. Default 53
-f <x> or --fuzzed-data <x>		: Specify that <x> prercent (out of 100) of packets sent are fuzzed. Default 50
-r <file> or --replay <file>		: Specify to replay the file <file>.
-m <seeds> or --max-seeds <seeds>	: Specify that the max number of seeds to be saved in crash file is <seeds>. Default 20
-t or --tcp				: Specify to use tcp instead of udp.
-h or --help				: Print the help menu.

Crash Detection: Must pick one

-n <name> or --pname <name>		: Specify that the pid associated with the process name <name> is to be used.
-d <pid> or --pid <pid>			: Specify that the pid <pid> is to be used.
-c <x> or --conn-check <x>		: Specify that <x> number of queries without response are to be used.
-e or --tcp-check			: Specify that a tcp handshake is to be used. Must be with a tcp connection.
```

Now with the crash detection, you have four different options (however you must pick one). Pname and pid are essentially the same, it's just pname will use `pidof` to look up the pid for the process name you pass to it. Conn-check essentially just checks to see if it is getting output from the target (not the most reliable). It will go report a crash when it sees no output from the target after sending <x> different inputs in a row. Then there is the tcp check which just tries to do a tcp hand shake, useful when dealing with things like zone transfers and tcp dns servers.
 
To use it to fuzz a target at `127.0.0.1` at port `53` using the crash detection my monitoring the pid "2054" (to do this, you must have the same privileges as the target process):
```
$	python fuzz.py -i 127.0.0.1 -p 53 --pid 2054
```

or

```
$	sudo python fuzz.py -i 127.0.0.1 -p 53 -d 2054
```

To use it to fuzz a target at `127.0.0.1` at port `53` using the crash detection my monitoring the pid associated with the process name "./dns", with only sending valid data:

```
$	python fuzz.py --remote-ip 127.0.0.1 --port 53 --pname ./dns --fuzzed-data 0
```

or

```
$	python fuzz.py -i 127.0.0.1 -p 53 -n ./dns -f 0
```

To use report a crash after seeing no output from tagret after 20 inputs in a row, and report a maximum of 100 seeds for crash replay:
```
$	python fuzz.py -i 127.0.0.1 -p 53 --conn-check 20 -m 100
```

To use the tcp handshake crash detection, and to fuzz a tcp target at `127.0.0.1:53`:
```
$	python fuzz.py -i 127.0.0.1 -p 53 -t -e
```

### Crash Detection & Replay

When the fuzzer detects a crash, it will print out text like this then exit:
```
Sending Non-Corrupted Data:
Length of Packet: 12
Sending Non-Corrupted Data:
Length of Packet: 25
Crash detected
Crashed seeds are: 20
```

Upon detecting a crash, it will generate a file called `outputFile.txt` (if there is already a file named that, it will just append a number to it in increasing order). This file contains the seeds used by the fuzzer, and the command line arguments. With that you can replay the fuzzer's actions. To replay a crash file just use the `-r` flag. Since all of the arguments are saved in the `outputFile.txt`, you don't need to enter in the arguments you had (except for the pid since that would of changed, however it will prompt you for it so don't enter it in as a command line argument):

To replay a crash file that didn't use `--pid`:
```
$	python fuzz.py -r outputFile.txt
```

To replay a crash file that did use `--pid` with the new pid `2380`:
```
$	python fuzz.py -r outputFile.txt
Initializing fuzzer
What is the new pid? 2380
```

### N-Days / Bugs Found

My fuzzer has found N-Days and crashed the following targets (no super hard targets):
```
Dnsmasq 2.77
haneWIN DNS Server 1.5.3
TFTPD 32 v4.00
```

In addition to that, it has crashed 5 random dns servers off of github.

### misc

Also if you want, I did a little bit of documentation on how dns queries work in `dns.md`.
