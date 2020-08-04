#!/bin/bash

if [[ -z "$1" ]]; then
 echo "Specify 'up' to create docker network and vrrp containers or"
 echo "Specify 'down' to delete docker network and vrrp containers"
 exit 1
fi

case $1 in
 up)
  docker-compose -f vulnerable_vrrp_network.yml up -d
  docker exec -it vrrp_master iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  docker exec -it vrrp_slave iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  docker exec -it vrrp_victim route del -net 0.0.0.0/0
  docker exec -it vrrp_victim route add -net 0.0.0.0/0 gw 172.13.37.254
  ;;
 down)
  docker-compose -f vulnerable_vrrp_network.yml down
esac
