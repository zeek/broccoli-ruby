#!/usr/bin/env ruby

begin
  require 'bro' # If installed as a native extension
rescue LoadError
  require 'rubygems' # If install as a gem
  gem 'broccoli'
  require 'bro'
end

require 'ipaddr'
include Bro

Bro.debug_calltrace=false
Bro.debug_messages=false

SRC_STR  = "%s/%s [%u/%u] -> "
DST_STR  = "%s/%s [%u/%u], "
METADATA_STR = "%s start: %f, duration: %f, addl: '%s'\n"

def generic_conn(conn)
  begin
    ip = IPAddr.ntop(conn.id.orig_h).to_s
    printf SRC_STR, ip, conn.id.orig_p, conn.orig.size, conn.orig.state
    ip = IPAddr.ntop(conn.id.resp_h).to_s
    printf DST_STR, ip, conn.id.resp_p, conn.resp.size, conn.resp.state
    printf METADATA_STR, conn.service, conn.start_time, conn.duration, conn.addl
  rescue
    # For some reason, occasionally the IPAddr class doesn't like the 
    # network byte ordered strings that it receives.
    puts "oops - this seems to be a bug :)"
  end
end

bc = Bro::Connection.new("127.0.0.1:47758", BRO_CFLAG_RECONNECT)

bc.event_handler_for("connection_attempt")     { |conn| print "connection_attempt: "; generic_conn(conn) }
bc.event_handler_for("connection_established") { |conn| print "connection_established: "; generic_conn(conn) }
bc.event_handler_for("connection_finished")    { |conn| print "connection_finished: "; generic_conn(conn) }
bc.event_handler_for("connection_rejected")    { |conn| print "connection_rejected: "; generic_conn(conn) }

if bc.connect
  puts "connected"
  while bc.wait
    bc.process_input
  end
end
