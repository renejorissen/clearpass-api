#!/usr/bin/env python3
#------------------------------------------------------------------------------
#
# Script to "play" with time structures
#
#------------------------------------------------------------------------------

import time
import datetime

print("Time in seconds since the epoch: %s" %time.time())
print("Current date and time: " , datetime.datetime.now())
print("Or like this: " ,datetime.datetime.now().strftime("%y-%m-%d-%H-%M"))

print("Current year: ", datetime.date.today().strftime("%Y"))
print("Month of year: ", datetime.date.today().strftime("%B"))
print("Week number of the year: ", datetime.date.today().strftime("%W"))
print("Weekday of the week: ", datetime.date.today().strftime("%w"))
print("Day of year: ", datetime.date.today().strftime("%j"))
print("Day of the month : ", datetime.date.today().strftime("%d"))
print("Day of week: ", datetime.date.today().strftime("%A"))

date_time = '2018-06-25 00:00:01'
pattern = '%Y-%m-%d %H:%M:%S'
epoch1 = int(time.mktime(time.strptime(date_time, pattern)))
print(date_time, epoch1)

date_time = '2018-07-01 23:59:59'
pattern = '%Y-%m-%d %H:%M:%S'
epoch2 = int(time.mktime(time.strptime(date_time, pattern)))
print(date_time, epoch2)

epoch3 = epoch2 - epoch1
print(epoch3)


timestamp = 1532296800
value = datetime.datetime.fromtimestamp(timestamp)
time = value.strftime('%Y-%m-%d %H:%M:%S')
print("time is ", time)