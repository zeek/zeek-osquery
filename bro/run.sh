#!/bin/bash

#checking the path of configuration file
##################################################
file="configure.conf"
if [ -f "$file" ]
then
	echo "Running osquery scripts specified in $file ..."
else
	echo "$file not found."
fi

#read contents of configuration file 
#		&
#update table.bro files with subnet
##################################################
while IFS= read -r line
do
	#split table name and subnet group
	IFS='=' read -ra fields <<< "$line"
	#corresponding file name for table after removing whitespaces
	table_file="$(echo -e "${fields[0]}" | tr -d '[[:space:]]').bro"
	#corresponding subnet for table after removing whitespaces
	table_subnet="$(echo -e "${fields[1]}" | tr -d '[[:space:]]')"
	#check if the prewritten table.bro file exits?
	if [ -f "osquery/$table_file" ]
	then
		patternarray=`grep -n '}' osquery/$table_file | sed 's/^\([0-9]\+\):.*$/\1/' | tail -1`
		#delete initial entry for subscribe function
		sed -i /osquery::subscribe/d  osquery/$table_file
		#add newer one with updated subnet
		sed -i "${patternarray} i osquery::subscribe(ev, ${table_subnet});" osquery/$table_file
	else
		echo "$table_file not found."
	fi
	
done <"$file"

#write __load__.bro file
##################################################
#remove osquery/__load__.bro file
rm osquery/__load__.bro
#create new file
touch osquery/__load__.bro 
if [ -f "osquery/main.bro" ]
then
	echo "@load ./main" >> osquery/__load__.bro
else
	echo "main.bro does not exits"			
fi

while IFS= read -r line
do
	#split table name and subnet group
	IFS='=' read -ra fields <<< "$line"
	#corresponding file name for table after removing whitespaces
	table_file="$(echo -e "${fields[0]}" | tr -d '[[:space:]]').bro"

	if [ -f "osquery/$table_file" ]
	then
		echo "@load ./${fields[0]}" >> osquery/__load__.bro
	else
		echo "$table_file not found."
	fi
	
done <"$file"

echo "Running Bro"
#run bro with scripts
##################################################
bro osquery exit_only_after_terminate=T
