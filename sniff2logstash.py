#!/usr/bin/python3
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from apscheduler.triggers.interval import IntervalTrigger
from scapy.all import *
from collections import Counter
import time
import re
import socket

#Rafael Gassner 20/08/2022
#Script to sniff syslog packets, apply a sampling rate,
#aggregate data and periodically pack it to logstash.
#Log sample
#time="1658328792" action="Drop" originsicname="CN=name1,O=name2" dst="11.11.11.11"  rule_name="24.100_._._" product="VPN-1 & FireWall-1" proto="17" service="1251"  src="12.12.12.12"

LOGSTASH_HOST='10.10.10.10'
LOGSTASH_PORT='9000'
SYSLOG_PORT='515'
#Send data every n seconds
PACK_EVERY=300
#Number of aggregations to send
TOP_AGG=50
#Sampling rate. Use 1 to save every single log line.
SAMPLING_RATE=1
#fields that should be extracted from log lines
xfields={'aggregated_log_count'}
#aggregations
aggs = [
	['src'],
	['proto'],
	['service'],
	['originsicname'],
	['dst'],
	['action'],
	['product'],
	['rule_name'],
  ['src','dst'],
  ['src','service'],
  ['dst','service'],
  ['src','action'],
  ['dst','action'],
  ['src','dst','action'],
  ['src','dst','service'],
  ['src','dst','service','action']
	]

#sniff data
def sniff_packets():
    #where actual aggregated data is stored
    my_data=initialize_vars()
    now = datetime.now() # current date and time
    my_data['start']=int(now.timestamp())
    my_data['packet_counter']=0
    sniff(filter="udp port "+SYSLOG_PORT, prn=custom_action(my_data), store=False, timeout=PACK_EVERY)
    pack_data(my_data)

#This function works like a decorator to allow the parameter passage
def custom_action(my_data):
    #function to apply the sampling rate
    def sampling(packet):
        if my_data['packet_counter'] % SAMPLING_RATE == 0 :
            process_packet(packet,my_data)
        my_data['packet_counter']+=1
    return sampling

def process_packet(packet,my_data):
    #read packet payload
    #st=time.time()
    payload=packet[Raw].load.decode()
    #print(payload)
    extracted_re=dict()
    extracted_value=dict()
    #extract all values needed in aggregations into re and value dictionaries
    for field in xfields:
        extracted_re[field]=re.search(r''+field+'="(.*?)"',payload)
        if extracted_re[field]:
            extracted_value[field]=extracted_re[field].group(1).translate({ ord(c): None for c in ",=" })
            #deal with some field formatting
            if field == 'originsicname':
                #remove string after last dot
                extracted_value[field]=extracted_value[field].rsplit('.',1)[0]
    #for every aggregation, if all fields are present, add up the counter in my_data
    for agg in aggs:
        agg_name='-'.join(agg)
        result=[]
        #if all required fields for this aggregations exist in this packet:
        if set(agg).issubset(extracted_value):
            for item in agg:
                #create a list with all required values
                result.append(extracted_value[item])
            #if this log line contains aggregation, it should count as multiple lines
            #result is added as a tuple, since lists are not hashable
            if extracted_re['aggregated_log_count']:
                my_data[agg_name].update({tuple(result):int(extracted_value['aggregated_log_count'])})
            else:
                my_data[agg_name].update([tuple(result)])
            #create a secondary counter, with number of log lines
            my_data[agg_name+'-raw'].update([tuple(result)])
    #et=time.time()
    #print('line {} took {}'.format(my_data['packet_counter'],et-st))

def netcat(host, port, content):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))
    s.sendall(content.encode())
    s.shutdown(socket.SHUT_WR)
    while True:
        data = s.recv(4096)
        if not data:
            break
        print(repr(data))
    s.close()
    
#Data visualization or packing to logstash
def pack_data(my_data):
    #st=time.time()
    agg_types=['','-raw']
    for agg in aggs:
        agg_name='-'.join(agg)
        for agg_type in agg_types:
            mcounter=my_data[agg_name+agg_type]
            for item,c in mcounter.most_common(TOP_AGG):
                outstr=''
                for i,part in enumerate(agg):
                    outstr=outstr+part+'='+item[i]+','
                fout='start={}.000,agg={},{}log_count={},filter=fwlogs'.format(my_data['start'],agg_name+agg_type,outstr,c)
                netcat(LOGSTASH_HOST,LOGSTASH_PORT,fout)
                #print(fout)
    #et=time.time()
    #print('end packing {}'.format(et-st))
    
def initialize_vars():
    my_data=dict()
    #create counters with names from aggregations
    for agg in aggs:
        my_data['-'.join(agg)]=Counter()
        my_data['-'.join(agg)+'-raw']=Counter()
    #create a set with items that must be extracted from logs
    for agg in aggs:
        for item in agg:
            xfields.add(item)
    return my_data

#Create a background scheduler
scheduler = BackgroundScheduler()
#Create a trigger with the same (almost) interval that the sniffer is going to run
trigger = IntervalTrigger(seconds=PACK_EVERY)
#Add the job to the scheduler, allowing the maximum of 2 concurrent instances
scheduler.add_job(sniff_packets,trigger,max_instances=2, next_run_time=datetime.now())
#Run the scheduler
scheduler.start()
try:
    while True:
        #Do nothing, while the scheduler takes care of multiple concurrent executions
        time.sleep(1)

except (KeyboardInterrupt, SystemExit):
    scheduler.shutdown()
