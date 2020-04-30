# nftables blocklist downloader & converter

`nfblock` downloads an IP blocklist from `iblocklist.com` and
converts it to a file loadable directly by the `nft` utility.

## Usage example

The snippet of a `nftables` configuration file below shows how to

- create an empty blocklist set

- set up rules to filter input and output packets

- feed the set with downloaded and converted blocklist rules

```
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    set blocklist {
        type ipv4_addr ; flags interval ; auto-merge
    }

    set blockcounters { type ipv4_addr ; flags dynamic ; }

    chain input {
...
        # check against blocklist
        ct state new ip saddr @blocklist add @blockcounters { ip saddr counter } drop
...
        # count and drop any other traffic
        counter drop
    }

    chain output {
...
        ct state new,invalid ip daddr @blocklist add @blockcounters { ip daddr counter } drop
...
        # count and drop any other traffic
        counter drop
    }

}

include "/var/lib/nfblock/nfblock.nft"
```
