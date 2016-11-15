#!/usr/bin/env bash

# ENTRADA, a big data platform for network data analytics
# 
# Copyright (C) 2016 SIDN [https://www.sidn.nl]
#  
# This file is part of ENTRADA.
# 
# ENTRADA is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# ENTRADA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#  
# You should have received a copy of the GNU General Public License
# along with ENTRADA.  If not, see [<http://www.gnu.org/licenses/].

############################################################
##                                                        ##
##                                                        ##
##              ENTRADA configuration                     ##
##                                                        ##
##                                                        ##
############################################################

#home dir of entrada
export ENTRADA_HOME="/home/entrada/entrada-latest"
#tmp dir used for keep state files
export TMP_DIR="$ENTRADA_HOME/tmp/"

#decoder config file
export CONFIG_FILE="$ENTRADA_HOME/scripts/config/entrada-settings.properties"

#Impala deamon hostname for impala-shell to connect to
export IMPALA_NODE=""

#hdfs locations for storing data
export HDFS_HOME="/user/hive/entrada"

#input directories, subdirs must have same name as name server
export DATA_RSYNC_DIR="/home/entrada/captures"
#root directory for data input/output
export DATA_DIR="/home/entrada/pcap"
#number of days to keep old pcap files
export PCAP_DAYS_TO_KEEP=10
#remove input pcap files from original location after they are processed 
#if you are not using rsync to remove them then set this option to true.
export DELETE_INPUT_PCAP_FILES=false

#Log location
export ENTRADA_LOG_DIR="/var/log/entrada"

#name servers, seperate multiple NS with a colon ;
#or use the following line to automatically detect the name server sub directories.
#if using auto detect make sure the data for every (new) name server is uploaded
#in the correct temporal order.
export NAMESERVERS=`cd ${DATA_RSYNC_DIR}; ls -dm */ | tr '\n' ' ' |  tr ',' ';' | sed 's/[\/ ]//g'`

#java lib jar
export ENTRADA_JAR="entrada-latest.jar"
#start and max heap size for entrada pcap convertor
export ENTRADA_HEAP_SIZE=4096m

#security if Kerberos is enabled, otherwise keep empty
export KRB_USER=""
export KEYTAB_FILE="my.keytab"

#error mail recipient
export ERROR_MAIL=""


#HDFS directories for table files
export HDFS_DNS_STAGING="$HDFS_HOME/staging"
export HDFS_ICMP_STAGING="$HDFS_HOME/icmp-staging"
export HDFS_DNS_QUERIES="$HDFS_HOME/queries"
export HDFS_ICMP_PACKETS="$HDFS_HOME/icmp"

# table names
export IMPALA_DNS_STAGING_TABLE="dns.staging"
export IMPALA_ICMP_STAGING_TABLE="icmp.staging"
export IMPALA_DNS_DWH_TABLE="dns.queries"
export IMPALA_ICMP_DWH_TABLE="icmp.packets"

