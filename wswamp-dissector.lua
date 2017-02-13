-- -*- coding: utf-8 -*-
--
-- WAMP post-dissector in pure Lua.
--
-- Copyright (c) 2016-2017 Sebastiano Alberto D'Ali', Valentina Pagliuca, Giovanni Merlino
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

-- Import modules
json=require("json")
msgpack=require("msgpack")

-- Declare the protocol
local wamp_protocol=Proto("wamp", "Web Application Messaging Protocol")

-- Declare the message types
local vs_funcs = {
  [1]="HELLO",
  [2]="WELCOME",
  [3]="ABORT",
  [4]="CHALLENGE",    -- Advanced profile message
  [5]="AUTHENTICATE", -- Advanced profile message
  [6]="GOODBYE",
  [8]="ERROR",
  [16]="PUBLISH",
  [17]="PUBLISHED",
  [32]="SUBSCRIBE",
  [33]="SUBSCRIBED",
  [34]="UNSUBSCRIBE",
  [35]="UNSUBSCRIBED",
  [36]="EVENT",
  [48]="CALL",
  [49]="CANCEL",      -- Advanced profile message
  [50]="RESULT",
  [64]="REGISTER",
  [65]="REGISTERED",
  [66]="UNREGISTER",
  [67]="UNREGISTERED",
  [68]="INVOCATION",
  [69]="INTERRUPT",   -- Advanced profile message
  [70]="YIELD",
}

-- Declare the new fields
local f_type=ProtoField.uint16("wamp.type","Type",base.DEC,vs_funcs)
local f_realm=ProtoField.string("wamp.realm","Realm")
local f_reason=ProtoField.string("wamp.reason","Reason")
local f_session=ProtoField.string("wamp.session","Session")
local f_request=ProtoField.string("wamp.request","Request")
local f_error=ProtoField.string("wamp.err","Error")
local f_request_type=ProtoField.uint16("wamp.reqtype", "Request type", base.DEC, vs_funcs)
local f_topic=ProtoField.string("wamp.topic","Topic")
local f_publication=ProtoField.string("wamp.publ","Publication")
local f_subscription=ProtoField.string("wamp.sub","Subscription")
local f_procedure=ProtoField.string("wamp.proc","Procedure")
local f_registration=ProtoField.string("wamp.reg","Registration")
local f_signature=ProtoField.string("wamp.sign", "Signature")
local f_authmethod=ProtoField.string("wamp.authmet", "AuthMethod")
local f_details=ProtoField.string("wamp.det", "Details")
local f_options=ProtoField.string("wamp.opt", "Options")
local f_extra=ProtoField.string("wamp.extra", "Extra")
local f_arguments=ProtoField.string("wamp.arg","Arguments")
local f_argumentskw=ProtoField.string("wamp.argkw","ArgumentsKw")

-- Add the fields to the protocol
wamp_protocol.fields={f_type,f_realm,f_reason,f_session,f_request,f_request_type, f_error,f_topic,f_publication,f_subscription,
                      f_procedure,f_registration,f_signature,f_authmethod,f_details,f_options,f_extra,f_arguments,f_argumentskw}

-- Declare the fields we need to read
local f_tcp_stream=Field.new('tcp.stream')
local f_message=Field.new('websocket.mdec_pay')
local f_opcode=Field.new("websocket.dopcode")

-- Dissector function
function wamp_protocol.dissector(tvb, pinfo, tree)
  local message=''  -- storing the WAMP message
  local messages={} -- storing the batched WAMP messages
  local supported_serializer=true
  local batched=false
  local extensions
  -- If the packet belongs to a TCP stream and is a WS packet carrying some payload
  if f_tcp_stream() and f_message() then
    local tcp_stream_index=f_tcp_stream().value
    local websocket_subprotocol=_G.websocket_subprotocols[tcp_stream_index]
    extensions=_G.websocket_extensions[tcp_stream_index]
    -- If it is carrying a WS subprotocol, the subprotocol is WAMP, the payload 'text' or 'binary', and there are WS extensions
    if websocket_subprotocol and string.find(websocket_subprotocol, 'wamp') and (f_opcode().value==1 or f_opcode().value==2) and extensions then
      -- No-op: the message will be recognized as WAMP, but not be deserialized and dissected, due to unmanaged WS extensions
    -- If it is carrying a WS subprotocol, the subprotocol is WAMP with json serialization, the payload 'text'
    elseif websocket_subprotocol and websocket_subprotocol=='wamp.2.json' and f_opcode().value==1 then
      local json_message=f_message().value
      message=json:decode(json_message)
    -- If it is carrying a WS subprotocol, the subprotocol is WAMP with msgpack serialization, the payload 'binary'
    elseif websocket_subprotocol and websocket_subprotocol=='wamp.2.msgpack' and f_opcode().value==2 then
      local msgpack_message=''
      local bytes_message=f_message().range:bytes()
      for i=0, (bytes_message:len()-1) do
        value=bytes_message:get_index(i)
        msgpack_message=msgpack_message .. string.char(value)
      end
      message=msgpack.unpack(msgpack_message)
    -- If it is carrying a WS subprotocol, the subprotocol is WAMP with batched json serialization, the payload 'text'
    elseif websocket_subprotocol and websocket_subprotocol=='wamp.2.json.batched' and f_opcode().value==1 then
      local payload_string=f_message().value
      local json_messages=payload_string:split('\30')
      for k,v in pairs(json_messages) do
        messages[k]=json:decode(v)
      end
      batched=true
    -- If it is carrying a WS subprotocol, the subprotocol is WAMP with batched msgpack serialization, the payload 'binary'
    elseif websocket_subprotocol and websocket_subprotocol=='wamp.2.msgpack.batched' and f_opcode().value==2 then
      local offset=f_message().offset
      local length=f_message().len
      local fine=offset+length-1
      local payload_tvb=f_message().source
      while offset<fine do
        local msgpack_message_length=payload_tvb(offset, 4):uint()
        offset=offset+4
        local bytes_message=payload_tvb(offset,msgpack_message_length):bytes()
        local msgpack_message=''
        for i=0, (bytes_message:len()-1) do
          value=bytes_message:get_index(i)
          msgpack_message=msgpack_message .. string.char(value)
        end
        table.insert(messages, msgpack.unpack(msgpack_message))
        offset=offset+msgpack_message_length
      end
      batched=true
    else
      -- If not WAMP
      if not (websocket_subprotocol and string.find(websocket_subprotocol, 'wamp') and (f_opcode().value==1 or f_opcode().value==2)) then
      return
      -- If WAMP, with other serializations (WAMP message will be recognized, but not dissected)
      else
        supported_serializer=false
      end
    end
  -- If it does not belong to a TCP stream, or it belongs but is not WS (or contains no payload)
  else
    return
  end

  -- Add the procotol name in the corresponding column
  pinfo.cols.protocol = wamp_protocol.name
  local tvb_length=tvb():len()
  local wamp_length=f_message().range:len()
  local wamp_offset=tvb_length-wamp_length
  -- Add the WAMP subtree to the dissection tree
  local t_wamp = tree:add(wamp_protocol, tvb(wamp_offset), "Web Application Messaging Protocol")
  -- If WS extensions are present, dissection cannot proceed, as extensions are not supported, neither in this dissector nor in the WS one
  if extensions then
    t_wamp:add("Extensions not supported: the packet can't be dissected")
    pinfo.cols.info="No information"
    return
  end
  -- If the dissector does not support the required type of serialization, dissection cannot proceed
  if supported_serializer==false then
    t_wamp:add("Serializer not supported: the packet can't be dissected")
    pinfo.cols.info="No information"
    return
  end
  -- Dissect messages, first looking up if batched mode is on
  if batched==false then
    pinfo.cols.info='Single WAMP message'
    dissector(message, tree)
  else
    pinfo.cols.info='Multiple WAMP messages'
    for i=1, #messages do
      mex=messages[i]
      t_mex=t_wamp:add("Message " .. i )
      dissector(mex, t_mex)
    end
  end
end

-- Function for string splitting
function string:split(sep)
  local sep, fields = sep or ":", {}
  local pattern = string.format("([^%s]+)", sep)
  self:gsub(pattern, function(c) fields[#fields+1] = c end)
  return fields
end

-- Main dissecting function
function dissector(msg, tree)
  -- Adding the WAMP message type (it is the 1st table element which represents the message) to the dissection tree
  tree:add(f_type, msg[1])
  local message_type=vs_funcs[msg[1]] -- Store the string representing message type in a variable
  -- Messages for session establishment
  if message_type=='HELLO' then -- HELLO
    tree:add(f_realm, msg[2])
    tree:add(f_details, json:encode(msg[3]))
  elseif message_type=="WELCOME" then -- WELCOME
    tree:add(f_session, string.format('%.0f', msg[2]))
    tree:add(f_details, json:encode(msg[3]))
  elseif message_type=="CHALLENGE" then -- CHALLENGE (Advanced Profile)
    tree:add(f_authmethod, msg[2])
    tree:add(f_extra, json:encode(msg[3]))
  elseif message_type=="AUTHENTICATE" then -- AUTHENTICATE (Advanced Profile)
    tree:add(f_signature, msg[2])
    tree:add(f_extra, json:encode(msg[3]))
  -- Messages for session closing
  elseif message_type=="ABORT" or message_type=="GOODBYE"  then
    tree:add(f_details, json:encode(msg[2]))
    tree:add(f_reason, msg[3])
  -- Messages for 'Publish and Subscribe'
  elseif message_type=="SUBSCRIBE" then
   tree:add(f_request, string.format('%.0f', msg[2]))
    tree:add(f_options, json:encode(msg[3]))
    tree:add(f_topic, msg[4])
  elseif message_type=="SUBSCRIBED" then
    local t_request=tree:add(f_request, string.format('%.0f', msg[2]))
    t_request:prepend_text("SUBSCRIBE.")
    tree:add(f_subscription, string.format('%.0f', msg[3]))
  elseif message_type=="UNSUBSCRIBE" then
    tree:add(f_request, string.format('%.0f', msg[2]))
    tree:add(f_subscription, string.format('%.0f', msg[3]))
  elseif message_type=="UNSUBSCRIBED" then
    local t_request=tree:add(f_request, string.format('%.0f', msg[2]))
    t_request:prepend_text("UNSUBSCRIBE.")
  elseif message_type=="PUBLISH" then
    tree:add(f_request, string.format('%.0f', msg[2]))
    tree:add(f_options, json:encode(msg[3]))
    tree:add(f_topic, msg[4])
    if msg[5] then
      tree:add(f_arguments, json:encode(msg[5]))
    end
    if msg[6] then
      tree:add(f_argumentskw, json:encode(msg[6]))
    end
  elseif message_type=="PUBLISHED" then
    local t_request=tree:add(f_request, string.format('%.0f', msg[2]))
    t_request:prepend_text("PUBLISH.")
    tree:add(f_publication, string.format('%.0f', msg[3]))
  elseif message_type=="EVENT" then
    local t_subscription=tree:add(f_subscription, string.format('%0.0f', msg[2]))
    t_subscription:prepend_text("SUBSCRIBED.")
    local t_publication=tree:add(f_publication, string.format('%.0f', msg[3]))
    t_publication:prepend_text("PUBLISHED.")
    tree:add(f_details, json:encode(msg[4]))
    if msg[5] then
      local t_arguments=tree:add(f_arguments, json:encode(msg[5]))
      t_arguments:prepend_text("PUBLISH.")
    end
    if msg[6] then
      local t_argumentskw=tree:add(f_argumentskw, json:encode(msg[6]))
      t_argumentskw:prepend_text("PUBLISH.")
    end
  -- Messages for 'Remote Procedure Calls'
  elseif message_type=="REGISTER" then
    tree:add(f_request, string.format('%.0f', msg[2]))
    tree:add(f_options, json:encode(msg[3]))
    tree:add(f_procedure, msg[4])
  elseif message_type=="REGISTERED" then
    local t_request=tree:add(f_request, string.format('%.0f', msg[2]))
    t_request:prepend_text("REGISTER.")
    tree:add(f_registration, string.format('%.0f', msg[3]))
  elseif message_type=="UNREGISTER" then
    tree:add(f_request, string.format('%.0f', msg[2]))
    local t_registration=tree:add(f_registration, string.format('%.0f', msg[3]))
    t_registration:prepend_text("REGISTERED.")
  elseif message_type=="UNREGISTERED" then
    local t_request=tree:add(f_request, string.format('%.0f', msg[2]))
    t_request:prepend_text("UNREGISTER.")
  elseif message_type=="CALL" then
    tree:add(f_request, string.format('%.0f', msg[2]))
    tree:add(f_options, json:encode(msg[3]))
    tree:add(f_procedure, msg[4])
    if msg[5] then
      tree:add(f_arguments, json:encode(msg[5]))
    end
    if msg[6] then
      tree:add(f_argumentskw, json:encode(msg[6]))
    end
  elseif message_type=="CANCEL" then -- CANCEL (Advanced Profile)
    local t_request=tree:add(f_request, string.format('%.0f', msg[2]))
    t_request:prepend_text("CALL.")
    tree:add(f_options, json:encode(msg[3]))
  elseif message_type=="INVOCATION" then
    tree:add(f_request, string.format('%.0f', msg[2]))
    local t_registration=tree:add(f_registration, string.format('%0.f', msg[3]))
    t_registration:prepend_text("REGISTERED.")
    tree:add(f_details, json:encode(msg[4]))
    if msg[5] then
      local t_arguments=tree:add(f_arguments, json:encode(msg[5]))
      t_arguments:prepend_text("CALL.")
    end
    if msg[6] then
      local t_argumentskw=tree:add(f_argumentskw, json:encode(msg[6]))
      t_argumentskw:prepend_text("CALL.")
    end
  elseif message_type=="INTERRUPT" then -- INTERRUPT (Advanced Profile)
    local t_request=tree:add(f_request, string.format('%0.f', msg[2]))
    t_request:prepend_text("INVOCATION.")
    tree:add(f_options, json:encode(msg[3]))
  elseif message_type=="YIELD" then
    local t_request=tree:add(f_request, string.format('%.0f', msg[2]))
    t_request:prepend_text("INVOCATION.")
    tree:add(f_options, json:encode(msg[3]))
    if msg[4] then
      tree:add(f_arguments, json:encode(msg[4]))
    end
    if msg[5] then
      tree:add(f_argumentskw, json:encode(msg[5]))
    end
  elseif message_type=="RESULT" then
    local t_request=tree:add(f_request, string.format('%.0f', msg[2]))
    t_request:prepend_text("CALL.")
    tree:add(f_details, json:encode(msg[3]))
    if msg[4] then
      local t_arguments=tree:add(f_arguments, json:encode(msg[4]))
      t_arguments:prepend_text("YIELD.")
    end
    if msg[5] then
      local t_argumentskw=tree:add(f_argumentskw, json:encode(msg[5]))
      t_argumentskw:prepend_text("YIELD.")
    end
  -- Error messages
  elseif message_type=="ERROR" then
    tree:add(f_request_type, msg[2])
    local t_request=tree:add(f_request, string.format('%.0f', msg[3]))
    t_request:prepend_text(vs_funcs[msg[2]] .. '.')
    tree:add(f_details, json:encode(msg[4]))
    tree:add(f_error, msg[5])
    if msg[6] then
      tree:add(f_arguments, json:encode(msg[6]))
    end
    if msg[7] then
      tree:add(f_argumentskw, json:encode(msg[7]))
    end
  end
end

-- Register the dissector as post dissector
register_postdissector(wamp_protocol)
