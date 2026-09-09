# Addrman health

A single-page dashboard for inspecting a Bitcoin Core `peers.dat`.

Everything is parsed in the browser. The file never leaves your machine and
nothing is written back.

## Use it

Open `index.html`, or visit the published page, and choose a `peers.dat`.
Copy the file first — a running node rewrites it every 15 minutes.

    cp ~/.bitcoin/peers.dat /tmp/peers.dat

## What it shows

The page opens with a check-list covering three aspects of addrman health —
reachability, eclipse resistance, and the ability to evict stale entries — each
row ticked or crossed against the loaded file. Below that are the charts the
checks are drawn from: age and network distribution, `nRefCount`, connection
attempts, third-party reachability, `IsTerrible()` arms, addresses held on many
ports, and netgroup / source-netgroup concentration.

Bucket placement is reproduced the way Core does it on load — `GetTriedBucket`
and `GetBucketPosition` from `src/addrman.cpp`, including the double-SHA256 and
the `GetGroup()` byte layout — so tried entries land in their real buckets
rather than in file order. `peersdat.js` carries that implementation.

## Reachability data

`reachable-data.js` holds a daily node export from bitnod.es, wrapped as a
script assignment because the site sends no `Access-Control-Allow-Origin`
header and a browser will not let the page fetch it directly.

Refresh it with:

    ./refresh-reachable.sh              # newest CSV on the explorer page
    ./refresh-reachable.sh 2026-08-11   # a specific day

The export covers IPv4, IPv6 and onion only. It has no I2P or CJDNS rows, so
entries on those networks are left out of the reachability ratio rather than
counted as unreachable.

## Files

    index.html          the dashboard
    peersdat.js         peers.dat parser + addrman bucket selection
    reachable-data.js   bitnod.es node export (generated)
    refresh-reachable.sh
