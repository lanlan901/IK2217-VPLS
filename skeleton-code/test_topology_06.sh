#!/bin/bash

#MYCUSTOMTAB='  '

declare -A hosts_connectivity
hosts_connectivity=( ["h1"]="h2" ["h2"]="h1" ["h3"]="h4 h5 h6" ["h4"]="h3 h5 h6" ["h5"]="h3 h4 h6" ["h6"]="h3 h4 h5" )

declare -A hosts_ips
hosts_ips=( ["h1"]="10.0.0.1" ["h2"]="10.0.0.2" ["h3"]="10.0.0.1" ["h4"]="10.0.0.2" ["h5"]="10.0.0.3" ["h6"]="10.0.0.4" )


rm results.txt
rm results.log
rm matrix.txt
echo ".  h1 h2 h3 h4 h5 h6" >> matrix.txt
#echo ". h1 h2 h4 h7" >> matrix.txt

for host1 in h1 h2 h3 h4 h5 h6
#for host1 in h1 h2 h4 h7
do
	raw="$host1 "
	#for host2 in h1 h2 h4 h7 
	for host2 in h1 h2 h3 h4 h5 h6
	do
		if [ "$host1" == "$host2" ]; then
			raw=`echo "$raw  V"` 
			continue
		fi

		mx $host2 bash run_server.sh  &
		sleep 1
		mx $host1 bash run_client.sh "${hosts_ips[$host2]}"
		outcome=`cat result.txt | grep "Connection refused" | wc -l`
		outcome2=`cat result.txt | grep "unable to connect to server" | wc -l`
		sudo killall iperf3

		#./run_server.sh h2 &
		#sleep 1
		#./run_client.sh h1 10.0.0.2 
		#outcome=`./run_client.sh h1 10.0.0.2 | grep "Sent 1 datagrams" | wc -l`
		#echo $outcome
		connectivity=`echo ${hosts_connectivity[$host1]} | grep $host2 | wc -l`
		if [ "$outcome" -eq '0' ] && [ "$outcome2" -eq '0' ]; then
			if [ "$connectivity" -eq "1" ]; then
				echo "$host1 to $host2 - Packet transmitted - SUCCEDED TEST " >> results.txt
				raw=`echo "$raw  V"`
			else
				echo "$host1 to $host2 - Packet transmitted -   FAILED TEST " >> results.txt
				raw=`echo "$raw  V"`
			fi
		else
			if [ "$connectivity" -eq "1" ]; then
				echo "$host1 to $host2 - Packet dropped    -   FAILED TEST " >> results.txt
				raw=`echo "$raw  -"`
			else
				echo "$host1 to $host2 - Packet dropped    - SUCCEDED TEST " >> results.txt
				raw=`echo "$raw  -"`
			fi
		fi
		echo "$host1 to $host2" >> results.log
		cat result.txt >> results.log
		rm result.txt
	done
	echo $raw >> matrix.txt
done

cat results.txt
echo ""
echo "OUTCOME"
column -t -s' ' matrix.txt

echo ""
echo "EXPECTED"
echo ".  h1 h2 h3 h4 h5 h6" > matrix.txt
#echo ". h1 h2 h4 h7" > matrix.txt
#for host1 in h1 h2 h4 h7
for host1 in h1 h2 h3 h4 h5 h6
do
	raw="$host1 "
	#for host2 in h1 h2 h4 h7
	for host2 in h1 h2 h3 h4 h5 h6
	do
		if [ "$host1" == "$host2" ]; then
			raw=`echo "$raw  V"` 
			continue
		fi
		connectivity=`echo ${hosts_connectivity[$host1]} | grep $host2 | wc -l`
		if [ "$connectivity" -eq "1" ]; then
			raw=`echo $raw '  ' V` 
		else
			raw=`echo "$raw  -"` 
		fi
	done
	echo $raw >> matrix.txt
done
column -t -s' ' matrix.txt
rm matrix.txt
