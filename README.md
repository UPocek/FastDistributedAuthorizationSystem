# FastDistributedAuthorizationSystem

## Problem

## Solution

### Infrastructure
- Level db is just a library and does not have Docker image so install it with other go libraries just by running the `go get .` and `go mod tidy` commands
- Consul among a lot of cool features has its Key-Value store. Create consul-config.json file with needed configuration and then start the container with this command `docker run -p 8500:8500 -p 8600:8600/udp --name=consul -v ./consul-config.json:/consul/config/consul-config.json hashicorp/consul agent -server -bootstrap -ui -client=0.0.0.0 -config-file=/consul/config/consul-config.json`

### Referances
- https://hub.docker.com/r/hashicorp/consul

- https://developer.hashicorp.com/consul/api-docs/kv#raw
- https://developer.hashicorp.com/consul/docs/dynamic-app-config/kv/store?utm_source=docs
- https://developer.hashicorp.com/consul/docs/dynamic-app-config/kv
- https://github.com/hashicorp/consul?tab=readme-ov-file