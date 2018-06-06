import gzip
import time
import datetime
import re
import json,re,argparse

parser=argparse.ArgumentParser(description='Generate')
parser.add_argument('--files',dest='files', nargs='+', action='store',default=None,help='inputfile')
parser.add_argument('--start',dest='startTime',action='store',default=None,help='Start Time, yy-mm-dd hh:mm:ss, e.g 18-04-20 13:35:14')
parser.add_argument('--end',dest='endTime',action='store',default=None,help='End Time, yy-mm-dd hh:mm:ss, e.g 18-04-20 13:35:14.255')
args=parser.parse_args()

files = args.files
startTimeStamp = time.mktime(datetime.datetime.strptime(args.startTime, "%y-%m-%d %H:%M:%S").timetuple())
endTimeStamp = time.mktime(datetime.datetime.strptime(args.endTime, "%y-%m-%d %H:%M:%S").timetuple())

print startTimeStamp
print endTimeStamp
output = []

for file in files:
    if file.endswith("gz"):
        f=gzip.open(file,'rb')
    else:
        f= open(file, 'rb')
    for line in f:

        idx = 0
        #7580||18-05-06 17:30:47.275-07:00||polResolveEPg__||DBG4||fr=ifc_policymgr:2:2:6:0:11:1,to=ifc_policyelem:1:106:5:0:255:127,co=doer:0:0:0x56d4bf:1,si=0x6a05fffc9419c16:0x1dd||(envelope 0x3000000e10893: RECEIVE-BULK:RESPONSE[polResolve
        #5785||18-05-17 21:24:44.353+09:00||mit_update||INFO||co=doer:32:3:0x20a9f6d:14,dn=registry/class-9012/instdn-[uni/fabric/sectok]/ra-[topology/pod-1/node-334]-5-0-0-0-Subtree-mo||MIT MODIFY InstanceId: 188:326200 MoLocal || control bits = 104||../common/src/framework/./core/mo/Changer.cc||732
        try:
            pid = line.split('||')[0]
            timestampStrWithTZ = line.split('||')[1]
            process = line.split('||')[2]
            severity = line.split('||')[3]
            message = line.split('||')[4:-1]
            content = ""
        except:
            ## here are some xml contents
            continue
        # 18-04-20 13:35:14.255+00:00
        # 18-04-20 13:35:14.255

        result  =  re.search('(.+)[+|-]', timestampStrWithTZ)
        timestampStr =  result.groups()[0]

        timestamp = time.mktime(datetime.datetime.strptime(timestampStr, "%y-%m-%d %H:%M:%S.%f").timetuple())


        if ( (timestamp >= startTimeStamp) & (timestamp <= endTimeStamp) ):
            output.append({})
            output[idx-1]["pid"] = pid
            output[idx-1]["timestamp"] = timestamp
            output[idx-1]["process"] = process
            output[idx-1]["severity"] = severity
            output[idx-1]["message"] = message
            output[idx-1]["content"] = content
            output[idx - 1]["filename"] = file
            idx += 1

            print file + " : " + line



#print output