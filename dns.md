# DNS Query

This is a bit of documentation regarding how dns queries are structured / work while I was working on my dns fuzzer. Most of this info comes straight from the dns rfc https://www.ietf.org/rfc/rfc1035.txt. 

A DNS Query mainly consists of two portions, the header and the question sections in the following order.

```
+----------+
|  Header  |
+----------+
| Question |
+----------+
```

Although sometimes it can have a cookie appended to the end, after the question.

### Header

The header consists of 12 bytes (96 bits). Those 12 bytes are split up amongst 5 different values, and some flags.

The flags are comprised of the following values.

```
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |  9  |  10 |  11 |  12 |  13 |  14 |  15 |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|     |                       |     |     |     |     |                 |                       |
|  QR |        Opcode         |  AA |  TC |  RD |  RA |      Zero       |         RCODE         |
|     |                       |     |     |     |     |                 |                       |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
```

The variables have the following values/meanings:

QR:	Specifies if this is a query or a response. 1 for response, and 0 for query.

OPCODE:	Specifies what type of query it is. It can have the following values.
```
0:	Standard Query 	-	A query where they provide a DNS Name, and expect information about that back (such as an IP address).
1:	Inverse Query 	-	An Inverse (Reverse) query is where they try to get information like an IP address from a DNS Name.
2:	Status Query	-	A status query requests information about a zone/zones.
3 - 15:			-	These aren't currently specified in the rfc, so they are reserved for future use
```

AA: Authoritative Answer - If this bit is 1 in responses, it specifies that it is from an authoritative server (if it is 0, then it is from a secondary dns server). It is only valid in responses, so in queries this bit should be 0.

TC: Truncated - This bit signifies if the message is truncated with a 1 (if not, this bit is 0). 

RD: Recursion Desired - If this bit is one in a query, it specifies that recursion is desired. Recursion means that if the server cannot answer the query, it will query other dns servers and return their results. In responses it should be 0.

RA: Recursion Available - This bit is only valid in responses. If it is set to 1, it means that the server supports recursion (0 for no recursion support). In queries it is set to 0.

Zero: These three bits are reserved for future use, so at the moment they aren't used for anything. The rfc specifies they must be 0 in all queries and responses.

RCODE: This is the response code which says what type of response the server sent. In queries it is set to 0. The following values mean the following things:

```
0:	There were no errors
1:	Format Error - The dns server could not read / understand the query.
2:	Server Failure - There was a dns error with the dns server.
3:	Name Error - This specifies that the domain name in the query does not exist, it is only valid from an authoritative server.
4:	Not Implemented - The requested query is not supported by the dns server. 
5:	Refused - The dns server refuses to process the dns query.
```

The entire DNS query header is comprised of these values:

```
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |  9  |  10 |  11 |  12 |  13 |  14 |  15 |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|                                                                                               |
|                                               ID                                              |
|                                                                                               |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|     |                       |     |     |     |     |                 |                       |
|  QR |        Opcode         |  AA |  TC |  RD |  RA |      Zero       |         RCODE         |
|     |                       |     |     |     |     |                 |                       |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|                                                                                               |
|                                            QDCOUNT                                            |
|                                                                                               |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|                                                                                               |
|                                            ANCOUNT                                            |
|                                                                                               |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|                                                                                               |
|                                            NSCOUNT                                            |
|                                                                                               |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|                                                                                               |
|                                            ARCOUNT                                            |
|                                                                                               |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
```

The other 5 two byte (16 bit) values signify the following things:
```
ID: 		A value which is used to identify the query, and distinguish it amongst other requests.
QDCOUNT: 	A value which specifies the number of entries in the question section (so how many different queries are in this query).
ANCOUNT: 	A value which specifies the number of entries in the answer section (so how many answers are in the reply).
NSCOUNT: 	A value which specifies the number of authority records in the authority records section (used in replies).
ARCOUNT: 	A value which specifies the number of resource records in the additional records (essentially record returned by dns response) section.
```

### Question

The question section is comprised of the three following values per question:

```
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |  9  |  10 |  11 |  12 |  13 |  14 |  15 |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|                                                                                               |
|                                             QNAME                                             |
|                                                                                               |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|                                                                                               |
|                                             QTYPE                                             |
|                                                                                               |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
|                                                                                               |
|                                             QCLASS                                            |
|                                                                                               |
+-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----|-----+
```

QNAME: This isn't a two byte value (despite the graphic above). It contains the identifying info for what your asking about. For instance if you are looking for an A record for the dns name `github.com` the QNAME would specify `github.com`. Each octet is split up into individual sections, where the length is specified with a one byte value that is prepended to each octet. After all of the sections, the QNAME is terminated with a null byte. For instance the qname for `github.com` would be this:

```
0x06	0x67	0x69	0x74	0x68	0x75	0x62	0x03	0x63	0x6f	0x6d	0x00
6	"g"	"i"	"t"	"h"	"u"	"b"	3	"c"	"o"	"m"	null byte terminal
```

QTYPE:	Specifies the type of query. The following values correspond to the following types. This list doesn't cover all of them, for more info check out https://en.wikipedia.org/wiki/List_of_DNS_record_types:

```
1:		A 	-	Maps a dns name to an IP address
2:		NS 	-	Designates the dns server's dns name for the zone.
3:		MD	-	Obsolete Mail Destination record, replaced with MX record
4:		MF	-	Obsolete Mail Forward record, replaced with MX record
5:		CNAME	-	Used to alias one dns name to another.
6:		SOA	-	A mandatory record for all zones, designates info such as primary name server, update timestamp, the zone's admin.
7:		MB	-	Obsolete Mail Box record
8:		MG	-	Obsolete Mail Group record
9:		MR 	- 	Obsolete Mail Rename record
10:		NULL 	-	Records used as place holders in experimental extensions of dns, cannot be in master files
11:		WKS 	-	Specifies well known services for an IP address
12:		PTR 	-	Reverse dns record, maps an IP address to a dns name
13:		HINFO 	-	Maps some info to a particular host
14:		MINFO 	-	Maps some info to a mailbox or mail list
15:		MX 	-	Says where mail for a zone should be delivered
16:		TXT 	-	Maps a text entry to a particular string
```

In addition to that, there are other types of resource records (referred to as pseudo records) which query a lot of records about a zone:
```
251:	IXFR	-	Incremental Zone transfer, basically and AXFR byt from the previous serial number
252:	AXFR	-	Authoritative Zone Transfer, requests entire zone file (all dns records)
255:	* (any)	-	Requests all records of all types known to the name server
```

QCLASS: A two byte value (16 bit) which specifies the class of the dns record. The following values correspond to the following classes:

```
1:	IN - Internet (this is the main one that is used )
3:	CH - Chaos Class which is mainly used in Chaosnet
4:	HS - Hesiod Class which will allow you to authentication info in dns queries, so you don't need an authentication system like ldap. 
```

### DNS Cookies

DNS cookies are used ad a security mechanism to help prevent certain types of attacks. The first step of how it works, is the client appends a dns cookie to it's query that it sends to the server (eight byte cookie). The dns server will take the ip address, client cookie, and specific information known to the server and generate a server cookie with it (it is a variable size, eight to 32 bytes). The server cookie will be appended to the end of the dns response, and the client will be expected to send the server cookie in future queries. The dns server will then be able to take the client cookie, the ip address, and the info known to it and generate a server cookie which should be the same one the server sends. This way it can hopefully validate that it has dealt with the client before.

A DNS Cookie is sent as an optional resource record (opt rr). The structure of an opt rr is this:
```
Name:	-	A one byte int detailing the domain name, must be set to 0 for root domain.
Type:	-	A two byte into detailing the type of record this is, should be 41 (0x29).
Class:	-	A two byte int that represents the max number of octets which the client can be received and processed by the client.
TTL:	-	A four byte int, Specifies the flags and the RCODE
RDLen:	-	A two byte int that is the size of the RData segment (which is the data sent with the record).
RData:	-	The data sent with the option record.
```

For the dns cookie, it has the following structure:
```
option code:	-	A two byte int representing what option it is (0x0a for cookie)
option len:	-	A two byte int representing the length of the cookie (0x8)
client cookie:	-	eight bytes representing the cookie
```

For the purpose of my fuzzer, I set the following values accordingly:
```
Name:	0x00 (1 byte)
Type:	0x00 0x29 (2 bytes)
Class:	2 random bytes
TTL:	0x00 0x00 0x00 0x00 (4 bytes)
RDLen:	0x00 0x0c (2 bytes)

RData is the cookie
option code:	0x00 0x0a (2 bytes)
cookie len:		0x00 0x08 (2 bytes)
cookie:			8 random bytes
```

For more info, checkout the rfc for opt rrs https://tools.ietf.org/html/rfc6891 and dns cookies https://tools.ietf.org/html/rfc7873.

Also when you have a dns cookie, you have to update ARCount accordingly (increase it by one). 

### AXFR

AXFR is a pseudo dns record that requests that the zone file (file on the dns server that holds all of the dns records) is transmitted. The rfc can be found here https://tools.ietf.org/html/rfc5936. The structure of an AXFR query is similar to that of a normal query (it has a header, and a question section). The question section has the name of the domain:

```
length:		a two byte int for the length of the query (number of bytes after this value)

ID:			two byte int identifying the query
Flags:		two byte int, all of the flags for an axfr query should be 0	
QDCount:	two byte int, should be 1 for 1 question
ANCount:	two byte int, should be 0 for no questions
NSCount:	two byte int, should be 0 for no records in authority section
ARCount:	two byte int for how many records in additional section, I have it set to one for the dns cookie

QName:		the domain name prepared like a normal query (split up by octets with the length of the octet prepended to the octet as a single byte)
QType:		a two byte int for the type of query, it should be 0xfc (252) for AXFR
QClass:		a two byte int for the class of the zone, usually will be 0x1 for IN (Internet)
```

One thing about this, I couldn't find in the rfc that the `length` was needed. However I saw in examples with other tools that do a zone transfer that it did this. In addition to that I couldn't get a successful zone transfer with bind until I added that value. Also zone transfers (AXFRs) are done over tcp versus udp.

### Any

Any is another pseudo dns record that requests any dns records that the dns server had access to. It is pretty much the same as an AXFR (including being over tcp versus udp). The difference is with the QType being 0xff (255) for Any.

```
length:		a two byte int for the length of the query (number of bytes after this value)

ID:			two byte int identifying the query
Flags:		two byte int, all of the flags for an axfr query should be 0	
QDCount:	two byte int, should be 1 for 1 question
ANCount:	two byte int, should be 0 for no questions
NSCount:	two byte int, should be 0 for no records in authority section
ARCount:	two byte int for how many records in additional section, I have it set to one for the dns cookie

QName:		the domain name prepared like a normal query (split up by octets with the length of the octet prepended to the octet as a single byte)
QType:		a two byte int for the type of query, it should be 0xff (255) for Any
QClass:		a two byte int for the class of the zone, usually will be 0x1 for IN (Internet)
```
