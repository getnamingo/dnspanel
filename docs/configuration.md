# Configuration Guide

This document explains how to configure Namingo Domain Manager after installation.  
If you have not installed the panel yet, please start with **[install.md](install.md)**.

---

## Overview

Namingo Domain Manager supports two types of DNS providers:

1. **Cloud-based DNS providers**
   - Example: Cloudflare, DNSimple, AnycastDNS, etc.
   - API-based configuration using `.env`
   - Zones are created using each provider’s API

2. **Self-hosted DNS servers**
   - Supported:
     - **PowerDNS**
     - **BIND9**
   - Domain Manager connects to your master and slave servers through an API layer

All configuration is done using your **`.env` file**, located in the directory where Domain Manager is installed.

---

# 1. Cloud-Based DNS Providers

## Add API credentials

Open your `.env` file and add the authentication values for each provider you want to use.

Example (Cloudflare):

```env
DNS_CLOUDFLARE_API_KEY=your_key_here
```

# 2. Self-hosted DNS servers

## Configure Your Nameservers (NS1 to NS13)

Add the list of your nameservers to the `.env` file.  
This defines the master (`ns1`) and any slave servers (`ns2`–`ns13`), so Domain Manager can insert the correct NS records automatically when creating new zones.

```env
# Nameservers (NS1 to NS13)
DNS_NS1=ns1.example.com.
DNS_NS2=ns2.example.com.
DNS_NS3=ns3.example.com.
DNS_NS4=ns4.example.com.
DNS_NS5=ns5.example.com.
DNS_NS6=ns6.example.com.
DNS_NS7=ns7.example.com.
DNS_NS8=ns8.example.com.
DNS_NS9=ns9.example.com.
DNS_NS10=ns10.example.com.
DNS_NS11=ns11.example.com.
DNS_NS12=ns12.example.com.
DNS_NS13=ns13.example.com.
```

## PowerDNS Configuration

If you host your own DNS using **PowerDNS**, you must enable the PowerDNS REST API on every master and slave server.

Below is the **required** `pdns.conf` **example:**

```ini
launch=gmysql
gmysql-host=127.0.0.1
gmysql-user=pdns
gmysql-password=yourStrongPassword
gmysql-dbname=powerdns
gmysql-dnssec=yes

# API
api=yes
api-key=sample_key_01_XYZ987654321
webserver=yes
webserver-address=0.0.0.0
webserver-allow-from=0.0.0.0/0,::/0
webserver-port=8081

# DNSSEC
default-ksk-algorithm=ed25519
default-zsk-algorithm=ed25519

# SOA Defaults
default-soa-mname=ns1.example.com.
default-soa-rname=hostmaster.example.com.

setuid=pdns
setgid=pdns
```

All PowerDNS servers (master + slaves) should be configured similarly.

### .env for PowerDNS

Edit `.env`:

```env
DNS_POWERDNS_API_KEY=sample_key_01_XYZ987654321
DNS_POWERDNS_POWERDNS_IP=127.0.0.1
```

If you have slave servers, copy both lines for each server and add the corresponding suffix (`_NS2`, `_NS3`, etc.).
Use the credentials for that specific server.

Example:

```env
DNS_POWERDNS_API_KEY=sample_key_01_XYZ987654321
DNS_POWERDNS_POWERDNS_IP=127.0.0.1

DNS_POWERDNS_API_KEY_NS2=sample_key_02_XYZ987654321
DNS_POWERDNS_POWERDNS_IP_NS2=192.168.1.10

DNS_POWERDNS_API_KEY_NS3=sample_key_03_XYZ987654321
DNS_POWERDNS_POWERDNS_IP_NS3=192.168.1.11
```

## BIND9 Configuration

For BIND-based DNS systems, Domain Manager integrates using the **bind9-api-server** project.

Install on **all** DNS servers (master and slave) [bind9-api-server](https://github.com/getnamingo/bind9-api-server) or [bind9-api-server-sqlite](https://github.com/getnamingo/bind9-api-server-sqlite).

### .env for BIND9

Edit `.env`:

```env
DNS_BIND_API_KEY=testUser:testPass
DNS_BIND_BIND_IP=127.0.0.1
```

If you have slave servers, copy both lines for each server and add the corresponding suffix (`_NS2`, `_NS3`, etc.).
Use the credentials for that specific server.

Example:

```env
DNS_BIND_API_KEY=testUser:testPass
DNS_BIND_BIND_IP=127.0.0.1

DNS_BIND_API_KEY_NS2=testUser2:testPass2
DNS_BIND_BIND_IP_NS2=192.168.1.10

DNS_BIND_API_KEY_NS3=testUser3:testPass3
DNS_BIND_BIND_IP_NS3=192.168.1.11
```

# 3. Apply Configuration & Create Zones

## Clear cache

After editing `.env`, run the following command from the Domain Manager install directory:

```bash
php bin/clear-cache.php
```

This reloads configuration and **enables the provider** in the UI.

## Create zones

In the UI click **Zones → New Zone** and you should now see the providers you configured.