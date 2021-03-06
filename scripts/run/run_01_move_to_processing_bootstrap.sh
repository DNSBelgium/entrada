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
#
# Move the received pcap files to the processing directory
# 
############################################################

PID=$TMP_DIR/run_01_move-pcap-to-staging_bootstrap

#----- functions ---------------

cleanup(){
  #remove pid file
  if [ -f $PID ];
  then
     rm $PID
  fi
}

# ------- main program -----------

echo "[$(date)] : Bootstrapping PCAP data move process"

if [ -f $PID ];
then
   echo "[$(date)] : $PID  : Process is already running, do not start new process."
   exit 1
fi

#create pid file
echo 1 > $PID

#Make sure cleanup() is called when script is done processing or crashed.
trap cleanup EXIT

nslist=$(echo $NAMESERVERS | tr ';' ' ')

parallel -j $PARALLEL_JOBS run_01_move_to_processing.sh ::: $nslist

echo "Moved data for all nameservers"

