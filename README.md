# README

This is an implementation of a plugin for Wireshark (tested under version 2.2.1): a post-dissector for the WAMP-over-WebSocket protocol, developed in Lua (version 5.2).

WAMP (Web Application Messaging Protocol) is a protocol that defines and enables messagging patterns among distributed application components and employs WebSocket (WS) as default transport layer.

The WAMP post-dissector depends (hence the prefix _post_) from another dissector, written for the WS protocol, included in this repo and written in Lua as well, thus not based on the native (built-in) Wireshark dissector for WS.

The Lua dissector for WS is listed as **_WS_** in Wireshark, to distinguish it from the default one, **_WEBSOCKET_**).

Note: in this README, any further reference to the WS dissector implies the dissector called **_WS_**, not **_WEBSOCKET_**.

#### Contents

The root folder includes 4 files, required to install and then enable dissecting WAMP:

- Dependencies

  - Libraries

    - *[json.lua]*, a Lua library for the JSON serialization format, imported in the post-dissector;
    - *[msgpack.lua]*, a Lua library for the MessagePack serialization format, imported in the post-dissector.

  - *ws-dissector.lua*, the WS dissector;


- *wswamp-dissector.lua*, the WAMP post-dissector.

In the repo there is a *clients* folder, which includes:

- the *general* subfolder, where there are WAMP client applications, written in Python, used to generate WAMP traffic and corresponding basic Wireshark traces;
- the *pubsub* and *rpc* subfolders, where there are WAMP client (backend plus frontend) application examples, written in Python, used to generate WAMP traffic and corresponding Pubblish-Subscribe and RPC Wireshark traces;

And the repo also contains a *traces* folder, which includes several Wireshark traces with WAMP traffic, captured by establishing a WAMP-over-WS session between a [Crossbar] router and a [WAMP client] written in Python, on the same host, per the following detail:

- the *general* subfolder:

  - *cbor_serializer.pcap*, generated with the *clients/general/register.py* client and with the router configured to use the batched CBOR serialization format for WAMP messages;
  - *event_with_args.pcap*, generated with the *clients/general/event_complex_payload.py* client and with the router configured to use the batched JSON serialization format for WAMP messages;
  - *event_no_args.pcap*, generated with the *clients/general/event_no_payload.py* client and with the router configured to use the batched JSON serialization format for WAMP messages;
  - *json_serializer2.pcap*, generated with the *clients/general/register.py* client (run twice) and with the router configured to use the batched JSON serialization format for WAMP messages;
  - *json_serializer.pcap*, generated with the *clients/general/register.py* client and with the router configured to use the batched JSON serialization format for WAMP messages;
  - *msgpack_serializer.pcap*, generated with the *clients/general/register.py* client and with the router configured to use the batched MessagePack serialization format for WAMP messages;
  - *register_call.pcap*, generated with the *clients/general/register.py* and *clients/general/call.py* client and with the router configured to use the batched JSON serialization format for WAMP messages;
  - *sub_reg_pub_call.pcap*, generated with the *clients/general/sub_register_pub_call.py* client and with the router configured to use the batched JSON serialization format for WAMP messages;
  - *ws_extensions.pcap*, generated with the *clients/general/register.py* client (run twice) and with the router configured to use the batched JSON serialization format for WAMP messages, as well as having WS protocol extensions enabled;
  - *ws_ping.pcap*, generated with the *clients/general/register.py* client and with the router configured to use the batched JSON serialization format for WAMP messages (in this case, ping/pong-type WS packet exchanges may be observed during the WAMP session).

- the *pubsub* and *rpc* subfolders, each in turn including a *json* and a *msgpack* one, for the JSON and MessagePack serializations (set up on the router), respectively, with as many traces for each subfolders as the aforementioned client examples, and numbered accordingly.

#### Install

1. Copy the Lua files (*json.lua*, *msgpack.lua*, *ws-dissector.lua* and *wswamp-dissector.lua*) available in the root folder of the repo to the Wireshark plugins folder (for example, *.wireshark/plugins* under macOS / Linux), without renaming them.
2. Run Wireshark.
3. Disable the default WS dissector (**_WEBSOCKET_**) and enable the plugins (**_WS_**, **_WAMP_**) in the **Analyze -> Enabled Protocols...** pop-up menu.

Wireshark is then ready to sniff and dissect any WAMP-over-WS messages passing over the wire.

#### Test

The post-dissector may be tested by starting packet captures under Wireshark, while a WAMP-enabled application is running and generating traffic over WS.
An easier alternative consists in loading previously captured traces of traffic inclusive of WAMP message-bearing packets transported over WS, such as the aforementioned traces which are already included in this repository.

In order to make use of the traces included here, an additional setup step is required: as these traces were captured with clients connecting to TCP port 8080 of the WAMP router (thus not the WS default one, TCP port 80) Wireshark must be instructed to engage the WS dissector for any traffic over TCP port 8080, by switching WS from the default port to the custom one in the Wireshark **Analyze -> Decode As...** option menu.

[json.lua]: <http://regex.info/code/JSON.lua>
[msgpack.lua]: <https://github.com/fperrad/lua-MessagePack/blob/master/src/MessagePack.lua>
[Crossbar]: <http://crossbar.io>
[WAMP client]: <http://autobahn.ws>
