-- -*- coding: utf-8 -*-
--
-- WebSocket dissector in pure Lua.
--
-- Copyright (c) 2016-2017 Emanuele Munafo', Sebastiano Alberto D'Ali', Valentina Pagliuca, Giovanni Merlino
-- https://github.com/mdslab/wamp-wireshark
--
-- Permission is hereby granted, free of charge, to any person obtaining a
-- copy of this software and associated documentation files (the
 --"Software"), to deal in the Software without restriction, including
 --without limitation the rights to use, copy, modify, merge, publish,
 --distribute, sublicense, and/or sell copies of the Software, and to
 --permit persons to whom the Software is furnished to do so, subject to
 --the following conditions:
--
-- The above copyright notice and this permission notice shall be included
-- in all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
-- OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
-- MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
-- IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
-- CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
-- TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
-- SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

-- Create a Proto object
local websocket_proto = Proto("WS", "WebSocket (WS) dissector")

-- Declare two global tables to store the WebSocket subprotocols and the WebSocket extensions, as set in the WebSocket handshake
_G.websocket_subprotocols={}
_G.websocket_extensions={}

-- Declare the field tcp.stream we need to obtain the stream index, in order to associate a WebSocket subprotocol to the corresponding TCP stream 
local f_tcp_stream=Field.new('tcp.stream')

-- Declare the string values for the opcodes (2nd byte of the header)
local vs_opcodes = {
  [0] = "Continuation frame",
  [1] = "Text frame",
  [2] = "Binary frame",
  [8] = "Connection Close",
  [9] = "Ping",
  [10] = "Pong",
}
local vs_boolcodes = {
  [0] = "False",
  [1] = "True"
}
local vs_pay_len = {
  [126] = "[126] Extended payload length (16 bits)",
  [127] = "[127] Extended payload length (64 bits)"
}
handshake_complete = 0;
-- Fields for the client handshake
local f_rmethod = ProtoField.string("websocket.rmethod", "Request Method")
local f_ruri = ProtoField.string("websocket.ruri", "Requested URI")
local f_rkey = ProtoField.string("websocket.key", "Sec-WebSocket-Key")
-- Fields for the server response handshake
local f_rcode = ProtoField.string("websocket.rcode", "Response Code")
local f_shttp = ProtoField.string("websocket.shttp", "HTTP protocol") -- HTTP version used by server
local f_subproto=ProtoField.string("websocket.subproto","Sec-WebSocket-Protocol")
local f_extens=ProtoField.string("websocket.extens", "Sec-WebSocket-Extensions")
-- Fields for the data-frame
---- 1st byte
local f_fin = ProtoField.uint8("websocket.dfin", "FIN", base.DEC, vs_boolcodes, 0x80) -- bitmask:0x80 => 128 => 10000000
local f_rsv1 = ProtoField.uint8("websocket.rsv1", "Reserved 1", base.DEC, vs_boolcodes, 0x40)
local f_rsv2 = ProtoField.uint8("websocket.rsv2", "Reserved 2", base.DEC, vs_boolcodes, 0x20)
local f_rsv3 = ProtoField.uint8("websocket.rsv3", "Reserved 3", base.DEC, vs_boolcodes, 0x10)
local f_opcode = ProtoField.uint8("websocket.dopcode", "OP Code", base.DEC, vs_opcodes, 0xF)
---- 2nd byte
local f_mask = ProtoField.uint8("websocket.dmask", "Mask", base.DEC, vs_boolcodes, 0x80)
local f_pay_len1 = ProtoField.uint8("websocket.dpaylen1", "Payload lenght", base.DEC, vs_pay_len, 0x7F)
---- Extra length header
local f_pay_len2 = ProtoField.uint32("websocket.dpaylen2", "Payload lenght", base.DEC)
local f_pay_len3 = ProtoField.uint64("websocket.dpaylen3", "Payload lenght", base.DEC)
---- Mask-key
local f_mkey = ProtoField.string("websocket.mkey", "Mask-Key")
---- Decoded payload
local f_mdecoded_pay = ProtoField.string("websocket.mdec_pay", "Decoded Payload")

websocket_proto.fields = {f_rmethod, f_ruri, f_rkey, f_rcode, f_shttp, f_subproto, f_extens, f_fin, f_rsv3, f_rsv2,
                          f_rsv1, f_opcode, f_mask, f_pay_len1, f_pay_len2, f_pay_len3, f_mkey, f_mdecoded_pay}

function websocket_proto.dissector(tvb, pinfo, tree)
  pinfo.cols.protocol = websocket_proto.name
  local t_websocket = tree:add(websocket_proto, tvb(), "Websocket")

  local websocket_key = nil -- Sec-WebSocket-Key if it is a client handshake
  local soffset = 0 -- Used as starting offset to scroll the buffer
  local offset = pinfo.desegment_offset or 0 -- Needed for reassembling stream
  -- tostring(buffer) returns the values of the buffer in a string type in HEX format
  if tvb:len()>=4 and tostring(tvb(0,4)) == "47455420" then -- Beginning of a HTTP request packet
    print("Start of semi-generic HTTP packet, is it a WebSocket handshake?");
    -- The method has to be GET [RFC6455], http ver > 1.1 : <GET /*pathhere* HTTP/1.1>
    hdr_str = tvb():string()
    handshake_offset = string.find(hdr_str, "Sec%-WebSocket%-Key")
    --[[
    -- The request MUST include a header field with the name |Sec-WebSocket-Key|.
    -- The value of this header field MUST be a nonce consisting of a randomly
    -- selected 16-byte value that has been base64-encoded[RFC6455]
    --]]
    if handshake_offset and not websocket_key then
      -- Take the WebSocket-Key so we are sure it is an handshake
      -- local key_offset = string.find(string.sub(hdr_str, handshake_offset), "\r\n")+handshake_offset
      websocket_key = string.sub(hdr_str, (handshake_offset+19), (handshake_offset+43))
      --[[
      -- The WS key should be 16-byte, encoded in Base64. A generic string of n bytes is represented
      -- in Base64 using 4*(n/3) chars to represent n bytes, and this need to be rounded up to a multiple of 4
      -- 8*(n/4) = 4*(16/3) = 21-> 24
      -- Take ascii code ex. "Ma" = 77 97 => tobin => 01001101 01100001 =>
      -- => take a group of 6 because log_2(64)= 6 and add padding!
      --]]
    end
    end_offset = string.find(hdr_str, "\r\n\r\n") -- End condition for an HTTP message: 2 consecutive CR/NL
    if not end_offset then -- Still not the end yet, go on with reassembling
      -- print("Going on reassembling..");
      -- See wireshark docs case(1) https://wiki.wireshark.org/Lua/Dissectors for this block
      pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
      pinfo.desegment_offset = 0
      return
    else
      ---- Here we have the full HTTP packet reassembled ----
      -- Ok, it is an handshake packet for WS, let's create the header tree item and set the info's column
      pinfo.cols.info = "Client handshake for WebSocket"
      local t_hdr = t_websocket:add(tvb(), "Header")
      t_hdr:add(f_rmethod, tvb(soffset, 3)) -- Request method [GET]
      soffset = soffset + 4
      t_hdr:add(f_ruri, tvb(soffset, getdifference_offset(tvb(soffset):string(), "%s"))) -- 0d0a
      t_hdr:add(f_rkey, tvb((handshake_offset+18), 23)) -- 18 not 19 because string indexing starts from 1, byte from 0
      ---- ----
      if not websocket_key then -- Can't find the must-have header field "Sec-WebSocket-Key"
        return 0 -- It was just a simple HTTP message, no handshake here
      end
    end
  ---- Handshake response ----
  elseif tvb:len()>=13 and tostring(tvb(9,4)) == "31303120" then -- HTTP response message (code 101 -> Switching Protocol)
    print("Start of semi-generic HTTP packet, is it a WebSocket handshake response?");
    hdr_str = tvb():string()
    handshake_offset = string.find(hdr_str, "Sec%-WebSocket%-Accept")
    -- Read some fields, if present
    local subprotocol_field=false
    local extensions_field=false
    local tcp_stream_index=f_tcp_stream().value
    -- Read the subprotocol field
    local websocket_subprotocol, subprotocol_field_offset, subprotocol_field_length=read_field(hdr_str, "Sec%-WebSocket%-Protocol")
    if websocket_subprotocol then
      _G.websocket_subprotocols[tcp_stream_index]=websocket_subprotocol -- Associate the WebSocket subprotocol to the corresponding TCP stream
      subprotocol_field=true
    end
    -- Read the extensions field
    local extensions, extensions_field_offset, extensions_field_length=read_field(hdr_str, "Sec%-WebSocket%-Extensions")
    if extensions then
      _G.websocket_extensions[tcp_stream_index]=extensions -- Associate the WebSocket extensions to the corresponding TCP stream
      extensions_field=true
    end
	
    if handshake_offset and not websocket_key then
      websocket_key = string.sub(hdr_str, (handshake_offset+22), (handshake_offset+50))
    end
    end_offset = string.find(hdr_str, "\r\n\r\n") -- End condition of HTTP message: 2 consecutive CR/NL
    if not end_offset then -- Still not the end yet, go on with reassembling
      print("Going on reassembling..");
      pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
      pinfo.desegment_offset = 0
      return
    else
      ---- Here we have the full HTTP packet reassembled ----
      -- Ok, it is an handshake packet for WS, let's create the header tree item and set the info's column
      handshake_complete = 1; -- There is an handshake, can check for data-frame later
      pinfo.cols.info = "Server response handshake for WebSocket"
      local t_hdr = t_websocket:add(tvb(), "Header")
      t_hdr:add(f_shttp, tvb(soffset, 8)) -- Request method [GET]
      soffset = soffset + 9
      t_hdr:add(f_rcode, tvb(soffset, getdifference_offset(tvb(soffset):string(), "%s"))) -- 0d0a
      t_hdr:add(f_rkey, tvb((handshake_offset+21), 28))
      if subprotocol_field then
        t_hdr:add(f_subproto, tvb(subprotocol_field_offset, subprotocol_field_length))
      end
      if extensions_field then
        t_hdr:add(f_extens, tvb(extensions_field_offset, extensions_field_length))
      end
      ---- ----
      if not websocket_key then -- Can't find the must-have header field "Sec-WebSocket-Accept"
        return 0 -- It was just a simple HTTP message, no handshake here
      end
    end
  ---- Data frame ----
  elseif handshake_complete then -- If there is a successful handshake in the previous packet, we can check for WS data frame
    local masked = 0 -- Flag used to know if the payload is masked
    local fin = tvb(0,1):bitfield(0,1);
    print("Start of semi-generic HTTP packet, is it a WebSocket data frame?");
    local mask_key
    local payload_len
    ---- Here we have the data frame ----
    pinfo.cols.info = "Data frame WebSocket"
    local t_hdr = t_websocket:add(tvb(0,2), "Header")
    -- Dissecting 1st byte
    local t_hfirst = t_hdr:add(tvb(0,1), "First byte")
    t_hfirst:add(f_fin, tvb(0,1)) -- FIN (1 bit)
    t_hfirst:add(f_rsv1, tvb(0,1)) -- RSVD1 field (1 bit)
    t_hfirst:add(f_rsv2, tvb(0,1)) -- RSVD2 field (1 bit)
    t_hfirst:add(f_rsv3, tvb(0,1)) -- RSVD3 field (1 bit)
    t_hfirst:add(f_opcode, tvb(0,1))
    -- Dissecting 2nd byte
    local t_hsecond = t_hdr:add(tvb(1,1), "Second byte")
    t_hsecond:add(f_mask, tvb(1,1)) -- Mask (1 bit)
    masked = tvb(1,1):bitfield(0,1)
    local t_hextra
    if tvb:len()>=4 then
      t_hextra = t_hdr:add(tvb(2,2), "Extra header")
    end
    -- Checking for payload lenght
    if(tvb(1,1):bitfield(1,7) == 126) then
      -- If 126, the following 2 bytes interpreted as a 16-bit unsigned integer are the payload length
      t_hsecond:add(f_pay_len1, tvb(1,1))
      t_hextra:add(f_pay_len2, tvb(2,2))
      payload_len = tvb(2,2):uint()
      soffset = 4
    elseif(tvb(1,1):bitfield(1,7) == 127) then
      -- If 127, the following 8 bytes interpreted as a 64-bit unsigned integer
      -- (the most significant bit MUST be 0) are the payload length
      t_hsecond:add(f_pay_len1, tvb(1,1))
      t_hextra:add(f_pay_len3, tvb(2,8))
      payload_len = tvb(2,8):uint64() -- To be tested: Lua has issues managing 64-bit integers
      soffset = 9
    else
      t_hsecond:add(f_pay_len1, tvb(1,1)) -- Payload length (7 bit): if 126 or 127, we need to read next byte as Extended Payload length
      payload_len = tvb(1,1):uint()
      soffset = 2
    end
    -- Get mask-key if the packet was masked (client -> server)
    local mask_key_offset
    if(masked == 1) then -- There is a mask-key
      t_hdr:add(f_mkey, tvb(soffset, 4))
      mask_key = tostring(tvb(soffset, 4))
      mask_key_offset=soffset
      soffset = soffset + 4
    end
    -- Payload
    local decoded_payload_string='' -- String to store the payload
    local decoded_payload_bytearray = ByteArray.new() -- ByteArray object to store the payload
    decoded_payload_bytearray:set_size(tvb(soffset):len())
    -- Copy payload bytes to the ByteArray object and to the string
    for i = 0, tvb(soffset):len()-1 do
      local decoded_byte
      -- Unmask payload byte
      if(masked == 1) then
        decoded_byte=bit32.bxor(tvb(soffset+i, 1):uint(), tvb(mask_key_offset+(i%4), 1):uint())
      -- Payload byte doesn't need unmask if not masked
      else
        decoded_byte=tvb(soffset+i, 1):uint()
      end
      decoded_payload_bytearray:set_index( i, decoded_byte)
      decoded_payload_string=decoded_payload_string .. string.char(decoded_byte)
    end
    local decoded_payload_tvb=ByteArray.tvb(decoded_payload_bytearray, "WebSocket payload decoded") -- Tvb object created to store the payload
    t_hdr:add(f_mdecoded_pay, decoded_payload_tvb(), decoded_payload_string)
  end
  ---- End of Data frame ----
end

-- Useful to read a handshake field
function read_field(packet_string, field_name)
  local row_offset
  local field_offset
  local field_end
  local field_length
  local field_value
  row_offset, field_offset = string.find(packet_string, field_name .. '%: ') -- Read the handshake field
  if row_offset then
    field_end=string.find(packet_string,"\r\n", field_offset)
    field_end=field_end-2 -- Offset and FINE are expressed in bytes
    field_length=field_end-field_offset+1
    field_value=string.sub(packet_string, field_offset+1, field_end+1)
  else
    return nil
  end
  return field_value, field_offset, field_length
end

-- Useful for HTTP, where each line (and thus fields in the headers) is separated by carriage return
function getdifference_offset(buffer, pattern)
  local newoffset = string.find(buffer, "%s")
  return newoffset
end

-- Load the TCP port table
local tcp_table = DissectorTable.get("tcp.port")

-- Register the protocol to port 80
tcp_table:add(80, websocket_proto)
