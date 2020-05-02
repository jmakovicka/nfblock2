# nftables blocklist downloader & converter

`nfblock` downloads an IP blocklist from `iblocklist.com` and
converts it to a file loadable directly by the `nft` utility.

## Usage example

The snippet of a `nftables` configuration file below shows how to

- create a blocklist set

- set up rules to filter input and output packets

```
#!/usr/sbin/nft -f

flush ruleset

include "/var/lib/nfblock/nfblock.nft"

table inet filter {
    set blocklist {
        type ipv4_addr ; flags constant, interval ; auto-merge ; elements = $blocklist_init
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
```
