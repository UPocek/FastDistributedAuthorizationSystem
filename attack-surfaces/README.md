# Attack surfaces analysis and mitigations

## Analysis

![img.png](img.png)

Main concerns are pretty obvious:
- Consul DB is exposed to the internet
- Connection to the DB is not encrypted
- Client to server communication is not encrypted

## Mitigations


