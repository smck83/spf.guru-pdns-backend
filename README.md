# spf.guru-pdns-backend
spf.guru pdns backend

````
docker run -it --name checkspf -e NS_RECORDS="my-primary-ns.example.org my-other-ns.example.com" -e ZONE="my.example.com" -p 8000:8000 ghcr.io/smck83/spf.guru-pdns-backend:latest
````


# run on local machine

1. download pdns.conf.example and docker-compose.yaml to your current directory
2. adjust docker-compose.yaml to use your ZONE, SOA_HOSTMASTER and NS_RECORDS
3. type `docker compose up`
4. test query e.g. `nslookup -q=txt i.23.2.89.167._d.sendgrid.net.my.example.org localhost`

expected response
````
Server:  UnKnown
Address:  ::1

i.23.2.89.167._d.sendgrid.net.my.example.org    text =

        "From the Guru's cards emerges 'PASS' beneath The Sun - clarity shines."
i.23.2.89.167._d.sendgrid.net.my.example.org    text =

        "v=spf1 ip4:167.89.2.23 ~all"

````
