#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <keyword>"
    echo "Example: $0 test1"
    exit 1
fi

test_case() {
    local test=$1
    local hex=${test}.hex
    local bin="${test}.bin"
    local domain_file="./../build/domain_names_${test}.txt"
    local translated_file="./../build/translated_${test}.txt"

    sudo ./dns-monitor -i lo -v -d ${domain_file} -t ${translated_file}&
    pid1=$!

    sleep 0.5

    xxd -r -p ${hex} > ${bin} ; nc -u -w1 127.0.0.1 53 < ${bin}
    pid2=$?

    wait $pid1
    status=$?
}

case "$1" in
    all) 
        echo "#################################################"
        echo "Testing: A, AAAA and NS:"
        echo "#################################################"
        test_case "dns_a_aaaa_ns"
        sleep 1
        
        echo "#################################################"
        echo "Testing: SOA:"
        echo "#################################################"
        test_case "dns_soa"
        sleep 1

        echo "#################################################"
        echo "Testing: MX:"
        echo "#################################################"
        test_case "dns_mx"
        sleep 1

        echo "#################################################"
        echo "Testing: Offline capture:"
        echo "#################################################"
        sudo ./../dns-monitor -p dns_a_aaaa_ns.pcapng -v -d ./../build/domain_names_offline.txt -t ./../build/translated_offline.txt 
        ;;

    a) ;&
    aaaa) ;&
    ns)
        test_case "dns_a_aaaa_ns"
        ;;
    soa)
        test_case "dns_soa"
        ;;
    mx)
        test_case "dns_mx"
        ;;
    offline)
        sudo ./../dns-monitor -p dns_a_aaaa_ns.pcapng -v -d ./../build/domain_names_offline.txt -t ./../build/translated_offline.txt 
        ;;
    *)
        echo "Unknown keyword: $1"
        echo "Supported keywords: test1, test2"
        exit 1
        ;;
esac

rm *.bin