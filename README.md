# spf.guru-pdns-backend
spf.guru pdns backend


docker run -it --name checkspf `
    -e NS_RECORDS="my-primary-ns.example.org my-other-ns.example.com" `
    -e ZONE="my.example.com" `
    -p 8000:8000 `
    ghcr.io/smck83/spf.guru-pdns-backend:latest
