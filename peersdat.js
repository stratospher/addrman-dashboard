/* peers.dat reader — shared by addrman-health.html (inlined at load) and the
 * node test harness. Pure functions, no DOM.
 *
 * File layout (src/addrdb.cpp SerializeDB + src/addrman.cpp AddrManImpl::Serialize):
 *   MessageStart (4)  ||  payload  ||  SHA256d(MessageStart || payload) (32)
 * payload:
 *   u8 format | u8 (32 + lowest_compatible) | nKey(32) | i32 nNew | i32 nTried
 *   | i32 nUBuckets^(1<<30) | nNew entries | nTried entries
 *   | per bucket: i32 count, count x i32 index | u256 asmap checksum (format >= 2)
 */
(function (root) {
  'use strict';

  var MAGICS = {
    f9beb4d9: 'mainnet', '0b110907': 'testnet3', '1c163f28': 'testnet4',
    '0a03cf40': 'signet', fabfb5da: 'regtest'
  };

  /* ---------- SHA3-256 (Keccak-f[1600], 32-bit lanes) ---------- */
  var RC_HI = [0,0,0x80000000,0x80000000,0,0,0x80000000,0x80000000,0,0,0,0,0,
               0x80000000,0x80000000,0x80000000,0x80000000,0x80000000,0,
               0x80000000,0x80000000,0x80000000,0,0x80000000];
  var RC_LO = [0x00000001,0x00008082,0x0000808a,0x80008000,0x0000808b,0x80000001,
               0x80008081,0x00008009,0x0000008a,0x00000088,0x80008009,0x8000000a,
               0x8000808b,0x0000008b,0x00008089,0x00008003,0x00008002,0x00000080,
               0x0000800a,0x8000000a,0x80008081,0x00008080,0x80000001,0x80008008];
  var ROT = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];

  /* Scratch reused across every permutation. Allocating these per round cost
   * ~680k array allocations over a 14k-onion peers.dat (3.4s -> see test). */
  var _bh = new Int32Array(5), _bl = new Int32Array(5);
  var _th = new Int32Array(5), _tl = new Int32Array(5);
  var _nh = new Int32Array(25), _nl = new Int32Array(25);

  function keccakF(sh, sl) {
    var bh = _bh, bl = _bl, th = _th, tl = _tl;
    for (var r = 0; r < 24; r++) {
      for (var x = 0; x < 5; x++) {
        var h = 0, l = 0;
        for (var y = 0; y < 5; y++) { h ^= sh[x + 5 * y]; l ^= sl[x + 5 * y]; }
        bh[x] = h; bl[x] = l;
      }
      for (var x2 = 0; x2 < 5; x2++) {
        var nx = (x2 + 1) % 5, px = (x2 + 4) % 5;
        var rh = (bh[nx] << 1) | (bl[nx] >>> 31);
        var rl = (bl[nx] << 1) | (bh[nx] >>> 31);
        var dh = bh[px] ^ rh, dl = bl[px] ^ rl;
        for (var y2 = 0; y2 < 5; y2++) { sh[x2 + 5 * y2] ^= dh; sl[x2 + 5 * y2] ^= dl; }
      }
      /* rho + pi into a scratch board */
      var nh = _nh, nl = _nl;
      for (var i = 0; i < 25; i++) {
        var xx = i % 5, yy = (i / 5) | 0;
        var dst = yy + 5 * ((2 * xx + 3 * yy) % 5);   /* B[y][2x+3y] = rot(A[x][y]) */
        var n = ROT[i], ah = sh[i], al = sl[i], oh, ol;
        if (n === 0) { oh = ah; ol = al; }
        else if (n < 32) { oh = (ah << n) | (al >>> (32 - n)); ol = (al << n) | (ah >>> (32 - n)); }
        else if (n === 32) { oh = al; ol = ah; }
        else { var m = n - 32; oh = (al << m) | (ah >>> (32 - m)); ol = (ah << m) | (al >>> (32 - m)); }
        nh[dst] = oh; nl[dst] = ol;
      }
      /* chi */
      for (var y3 = 0; y3 < 5; y3++) {
        for (var x3 = 0; x3 < 5; x3++) { th[x3] = nh[x3 + 5 * y3]; tl[x3] = nl[x3 + 5 * y3]; }
        for (var x4 = 0; x4 < 5; x4++) {
          sh[x4 + 5 * y3] = th[x4] ^ (~th[(x4 + 1) % 5] & th[(x4 + 2) % 5]);
          sl[x4 + 5 * y3] = tl[x4] ^ (~tl[(x4 + 1) % 5] & tl[(x4 + 2) % 5]);
        }
      }
      sh[0] ^= RC_HI[r]; sl[0] ^= RC_LO[r];
    }
  }

  /* SHA3-256: rate 136 bytes, domain padding 0x06 … 0x80 */
  function sha3_256(msg) {
    var RATE = 136;
    var sh = new Int32Array(25), sl = new Int32Array(25);
    var padded = new Uint8Array(Math.ceil((msg.length + 1) / RATE) * RATE);
    padded.set(msg);
    padded[msg.length] = 0x06;
    padded[padded.length - 1] |= 0x80;
    for (var off = 0; off < padded.length; off += RATE) {
      for (var i = 0; i < RATE; i += 8) {
        var j = (i / 8) | 0;
        sl[j] ^= padded[off+i] | (padded[off+i+1]<<8) | (padded[off+i+2]<<16) | (padded[off+i+3]<<24);
        sh[j] ^= padded[off+i+4] | (padded[off+i+5]<<8) | (padded[off+i+6]<<16) | (padded[off+i+7]<<24);
      }
      keccakF(sh, sl);
    }
    var out = new Uint8Array(32);
    for (var k = 0; k < 4; k++) {
      var lo = sl[k], hi = sh[k];
      out[k*8  ] = lo & 255; out[k*8+1] = (lo>>>8) & 255;
      out[k*8+2] = (lo>>>16) & 255; out[k*8+3] = (lo>>>24) & 255;
      out[k*8+4] = hi & 255; out[k*8+5] = (hi>>>8) & 255;
      out[k*8+6] = (hi>>>16) & 255; out[k*8+7] = (hi>>>24) & 255;
    }
    return out;
  }

  /* ---------- encodings ---------- */
  var B32 = 'abcdefghijklmnopqrstuvwxyz234567';
  function base32(bytes) {
    var out = '', bits = 0, val = 0;
    for (var i = 0; i < bytes.length; i++) {
      val = (val << 8) | bytes[i]; bits += 8;
      while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(val << (5 - bits)) & 31];
    return out;
  }
  function ipv4(b) { return b[0] + '.' + b[1] + '.' + b[2] + '.' + b[3]; }
  function ipv6(b) {
    var g = [];
    for (var i = 0; i < 16; i += 2) g.push(((b[i] << 8) | b[i+1]).toString(16));
    var best = -1, bestLen = 0, cur = -1, curLen = 0;
    for (var k = 0; k < 8; k++) {
      if (g[k] === '0') { if (cur < 0) { cur = k; curLen = 0; } curLen++;
        if (curLen > bestLen) { best = cur; bestLen = curLen; } }
      else cur = -1;
    }
    if (bestLen < 2) return g.join(':');
    return (g.slice(0, best).join(':')) + '::' + (g.slice(best + bestLen).join(':'));
  }
  function onionV3(pub) {
    var pre = [0x2e,0x6f,0x6e,0x69,0x6f,0x6e,0x20,0x63,0x68,0x65,0x63,0x6b,0x73,0x75,0x6d]; /* ".onion checksum" */
    var msg = new Uint8Array(pre.length + 32 + 1);
    msg.set(pre, 0); msg.set(pub, pre.length); msg[pre.length + 32] = 3;
    var ck = sha3_256(msg);
    var full = new Uint8Array(35);
    full.set(pub, 0); full[32] = ck[0]; full[33] = ck[1]; full[34] = 3;
    return base32(full) + '.onion';
  }

  var V1_MAPPED = [0,0,0,0,0,0,0,0,0,0,0xff,0xff];
  function decodeV1(b) {
    var mapped = true;
    for (var i = 0; i < 12; i++) if (b[i] !== V1_MAPPED[i]) { mapped = false; break; }
    if (mapped) return { network: 'ipv4', address: ipv4(b.subarray(12)), raw: b.subarray(12) };
    if (b[0] === 0xfd && b[1] === 0x87 && b[2] === 0xd8 && b[3] === 0x7e &&
        b[4] === 0xeb && b[5] === 0x43)
      return { network: 'onion', address: base32(b.subarray(6)) + '.onion', raw: b.subarray(6) };  /* onioncat torv2 */
    if ((b[0] & 0xff) === 0xfc) return { network: 'cjdns', address: ipv6(b), raw: b };
    return { network: 'ipv6', address: ipv6(b), raw: b };
  }
  function decodeV2(netId, b) {
    switch (netId) {
      case 1: return { network: 'ipv4',  address: ipv4(b), raw: b };
      case 2: return { network: 'ipv6',  address: ipv6(b), raw: b };
      case 3: return { network: 'onion', address: base32(b) + '.onion', raw: b };  /* torv2 */
      case 4: return { network: 'onion', address: onionV3(b), raw: b };
      case 5: return { network: 'i2p',   address: base32(b) + '.b32.i2p', raw: b };
      case 6: return { network: 'cjdns', address: ipv6(b), raw: b };
      default: return { network: 'unknown:' + netId, address: hex(b), raw: b };
    }
  }
  function hex(b) { var s = ''; for (var i = 0; i < b.length; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16); return s; }

  /* ---------- netgroup (NetGroupManager::GetGroup, no asmap) ----------
   * With an empty asmap GetGroup falls through to the net-class branches:
   *   IPv4 (incl. addresses with a linked IPv4)  -> /16
   *   he.net (2001:470::/32)                     -> /36
   *   other IPv6                                 -> /32
   *   Tor / I2P                                  -> 4 bits
   *   CJDNS                                      -> 12 bits (constant first byte skipped)
   * The local / internal / unroutable branches are unreachable here: AddSingle
   * rejects !IsRoutable() (addrman.cpp:535), so nothing unroutable is on disk.
   * Trailing bits are set to 1 exactly as GetGroup does, so a group key here
   * equals the byte string Core would bucket on. */
  function hexb(b){ var s=''; for (var i=0;i<b.length;i++) s+=(b[i]<16?'0':'')+b[i].toString(16); return s; }
  function v6label(b, bits) {
    var g = [], n = Math.ceil(bits/16);
    for (var i = 0; i < n*2; i += 2) g.push((((b[i]<<8)|b[i+1])>>>0).toString(16));
    return g.join(':') + '::/' + bits;
  }
  /* 6to4 (2002::/16), Teredo (2001:0::/32) and NAT64 (64:ff9b::/96) carry an
   * IPv4 inside, and Core groups them with that IPv4's /16. RFC6145 is not
   * handled — it is effectively unused on the network. */
  function linkedIPv4(b) {
    if (b[0]===0x20 && b[1]===0x02) return [b[2], b[3], '6to4'];
    if (b[0]===0x20 && b[1]===0x01 && b[2]===0x00 && b[3]===0x00)
      return [(~b[12])&255, (~b[13])&255, 'teredo'];
    if (b[0]===0x00 && b[1]===0x64 && b[2]===0xff && b[3]===0x9b) return [b[12], b[13], 'nat64'];
    return null;
  }
  function netGroup(network, b) {
    if (!b || !b.length) return {key:'?|'+network, label:network+' (undecodable)', net:network};
    if (network === 'ipv4' && b.length === 4)
      return {key:'1|'+b[0]+'.'+b[1], label:b[0]+'.'+b[1]+'.0.0/16', net:'ipv4'};
    if ((network === 'ipv6' || network === 'cjdns') && b.length === 16) {
      if (network === 'cjdns')
        return {key:'5|'+b[0]+'.'+(b[1]|0x0f),
                label:'cjdns /12 · '+hexb(b.subarray(0,1))+(b[1]>>4).toString(16)+'x', net:'cjdns'};
      var li = linkedIPv4(b);
      if (li) return {key:'1|'+li[0]+'.'+li[1],
                      label:li[0]+'.'+li[1]+'.0.0/16 ('+li[2]+')', net:'ipv4'};
      if (b[0]===0x20 && b[1]===0x01 && b[2]===0x04 && b[3]===0x70)
        return {key:'2|'+hexb(b.subarray(0,4))+'-'+(b[4]|0x0f),
                label:v6label(b,36).replace('/36','')+((b[4]>>4).toString(16))+'/36', net:'ipv6'};
      return {key:'2|'+hexb(b.subarray(0,4)), label:v6label(b,32), net:'ipv6'};
    }
    /* Tor/I2P keep only the top 4 bits of byte 0. base32 packs 5 bits per
     * character, so the leading character of the address determines the group:
     * each group is exactly the two characters B32[2n] and B32[2n+1]. */
    if (network === 'onion' || network === 'i2p') {
      var n4 = b[0] >> 4, pre = network === 'onion' ? '3|' : '4|';
      return {key: pre + (b[0]|0x0f),
              label: network + ' /4 · ' + n4.toString(16) + 'x  (' + B32[2*n4] + '/' + B32[2*n4+1] + '…)',
              net: network};
    }
    return {key:'?|'+network, label:network+' (ungrouped)', net:network};
  }

  /* Recover raw bytes from a rendered address, for the getrawaddrman path
   * which only carries strings. */
  var B32REV = (function(){ var m={}; for (var i=0;i<B32.length;i++) m[B32[i]]=i; return m; })();
  function unbase32(s) {
    var out=[], bits=0, val=0;
    for (var i=0;i<s.length;i++) {
      var c=B32REV[s[i]]; if (c===undefined) return null;
      val=(val<<5)|c; bits+=5;
      if (bits>=8) { out.push((val>>>(bits-8))&255); bits-=8; }
    }
    return new Uint8Array(out);
  }
  function parseV6(s) {
    var pct=s.indexOf('%'); if (pct>=0) s=s.slice(0,pct);
    var halves=s.split('::');
    if (halves.length>2) return null;
    var head=halves[0]?halves[0].split(':'):[];
    var tail=halves.length===2?(halves[1]?halves[1].split(':'):[]):null;
    if (tail===null && head.length!==8) return null;
    var groups;
    if (tail===null) groups=head;
    else {
      var fill=8-head.length-tail.length;
      if (fill<0) return null;
      groups=head.concat(Array(fill).fill('0'), tail);
    }
    var out=new Uint8Array(16);
    for (var i=0;i<8;i++) {
      var v=parseInt(groups[i]||'0',16);
      if (isNaN(v)||v<0||v>0xffff) return null;
      out[i*2]=v>>8; out[i*2+1]=v&255;
    }
    return out;
  }
  function addrBytes(network, s) {
    if (!s) return null;
    if (network === 'ipv4') {
      var p=s.split('.'); if (p.length!==4) return null;
      var o=new Uint8Array(4);
      for (var i=0;i<4;i++){ var v=+p[i]; if (!(v>=0&&v<=255)) return null; o[i]=v; }
      return o;
    }
    if (network === 'ipv6' || network === 'cjdns') return parseV6(s);
    if (network === 'onion') { var d=unbase32(s.replace(/\.onion$/,'')); return d?d.subarray(0,32):null; }
    if (network === 'i2p')   { var e=unbase32(s.replace(/\.b32\.i2p$/,'')); return e?e.subarray(0,32):null; }
    return null;
  }

  /* ---------- parser ---------- */
  function parsePeersDat(buffer) {
    var dv = new DataView(buffer), p = 0, len = buffer.byteLength;
    function need(n) { if (p + n > len) throw new Error('peers.dat is truncated at byte ' + p); }
    function u8()   { need(1); return dv.getUint8(p++); }
    function u16be(){ need(2); var v = dv.getUint16(p, false); p += 2; return v; }
    function i32()  { need(4); var v = dv.getInt32(p, true);  p += 4; return v; }
    function u32()  { need(4); var v = dv.getUint32(p, true); p += 4; return v; }
    function i64()  { need(8); var v = dv.getBigInt64(p, true); p += 8; return Number(v); }
    function u64big(){ need(8); var v = dv.getBigUint64(p, true); p += 8; return v; }
    function bytes(n){ need(n); var v = new Uint8Array(buffer, p, n); p += n; return v; }
    function csize() {
      var n = u8();
      if (n < 0xfd) return BigInt(n);
      if (n === 0xfd) { need(2); var a = dv.getUint16(p, true); p += 2; return BigInt(a); }
      if (n === 0xfe) { need(4); var b = dv.getUint32(p, true); p += 4; return BigInt(b); }
      return u64big();
    }

    var magic = hex(bytes(4));
    var network = MAGICS[magic] || null;

    var format = u8();
    var lowestRaw = u8();
    if (format < 1 || format > 8) {
      throw new Error('Unrecognised peers.dat format byte 0x' + format.toString(16) +
                      (network ? '' : ' (and unknown network magic ' + magic + ') — is this really a peers.dat?'));
    }
    var nKey = hex(bytes(32));
    var nNew = i32(), nTried = i32();
    if (nNew < 0 || nTried < 0 || nNew > 5e6 || nTried > 5e6)
      throw new Error('Implausible entry counts (new=' + nNew + ', tried=' + nTried + ') — file is probably not a peers.dat');
    var nUBuckets = i32() ^ (1 << 30);
    var v2 = format >= 3;

    function entry(table) {
      u32();                                   /* stored CAddress disk version */
      var time = u32();
      var services;
      if (v2) services = csize();
      else    services = u64big();
      var a, s;
      if (v2) {
        var nid = u8(), alen = Number(csize());
        if (alen > 512) throw new Error('Address length ' + alen + ' out of range at byte ' + p);
        a = decodeV2(nid, bytes(alen));
        var port = u16be();
        var snid = u8(), slen = Number(csize());
        if (slen > 512) throw new Error('Source length ' + slen + ' out of range at byte ' + p);
        s = decodeV2(snid, bytes(slen));
        return mk(table, time, services, a, port, s);
      }
      a = decodeV1(bytes(16));
      var port1 = u16be();
      s = decodeV1(bytes(16));
      return mk(table, time, services, a, port1, s);
    }
    function mk(table, time, services, a, port, s) {
      var last_success = i64();
      var nattempts = i32();
      var g = netGroup(a.network, a.raw);
      if (!groupLabels.has(g.key)) groupLabels.set(g.key, g.label);
      return {
        group: g.key,
        table: table, time: time,
        services: services <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(services) : services.toString(),
        address: a.address, network: a.network, port: port,
        source: s.address, source_network: s.network,
        last_success: last_success, nattempts: nattempts, refcount: 0
      };
    }

    var groupLabels = new Map();
    var rows = [], i;
    for (i = 0; i < nNew; i++)   rows.push(entry('new'));
    for (i = 0; i < nTried; i++) rows.push(entry('tried'));

    /* Bucket table — recovers nRefCount, which is memory-only in the struct, and
     * which bucket each reference sits in. The position WITHIN a bucket is not
     * stored: Core recomputes it via GetBucketPosition(nKey, ...) on load. */
    var bucketsRead = 0;
    var bucketTable = [];
    try {
      for (var b = 0; b < nUBuckets; b++) {
        var cnt = i32();
        if (cnt < 0 || cnt > 64) throw new Error('bucket size ' + cnt);
        var members = [];
        for (var k = 0; k < cnt; k++) {
          var idx = i32();
          if (idx >= 0 && idx < nNew) { rows[idx].refcount++; members.push(idx); }
        }
        bucketTable.push(members);
        bucketsRead++;
      }
    } catch (e) {
      /* leave refcounts partial rather than losing the whole parse */
    }
    var refcountOk = bucketsRead === nUBuckets;
    /* MakeTried() clears an entry from every new bucket, so a tried entry's
     * nRefCount is 0 — not 1. The bucket table only indexes the new array. */
    for (i = nNew; i < rows.length; i++) rows[i].refcount = 0;

    return {
      source: 'peersdat', rows: rows, format: format,
      lowestCompatible: lowestRaw - 32, network: network, magic: magic,
      nKey: nKey, nNew: nNew, nTried: nTried, nUBuckets: nUBuckets,
      refcountOk: refcountOk, bucketTable: bucketTable, groupLabels: groupLabels
    };
  }


  /* ---------- addrman bucket selection ----------
   * AddrInfo::GetTriedBucket and AddrInfo::GetBucketPosition, src/addrman.cpp.
   * peers.dat stores no tried bucketing at all and no slot index for new, so Core
   * recomputes both on load; this reproduces that.
   *
   *   GetTriedBucket:   h1 = H(nKey, GetKey())
   *                     h2 = H(nKey, GetGroup(), h1 % ADDRMAN_TRIED_BUCKETS_PER_GROUP)
   *                     return h2 % ADDRMAN_TRIED_BUCKET_COUNT
   *   GetBucketPosition: h  = H(nKey, 'N'|'K', bucket, GetKey())
   *                     return h % ADDRMAN_BUCKET_SIZE
   *
   * H is HashWriter — double SHA-256 — and GetCheapHash() is ReadLE64 of the digest.
   * Every modulus here is a power of two, so only the low bytes of the digest matter
   * and no 64-bit arithmetic is needed. */

  var K256 = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);

  function sha256(msg) {
    var H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                             0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    var ml = msg.length, withPad = ((ml + 9 + 63) >> 6) << 6;
    var m = new Uint8Array(withPad);
    m.set(msg, 0); m[ml] = 0x80;
    var bits = ml * 8;
    /* length is 64-bit big-endian; inputs here are far under 2^32 bits */
    m[withPad - 4] = (bits >>> 24) & 255; m[withPad - 3] = (bits >>> 16) & 255;
    m[withPad - 2] = (bits >>> 8) & 255;  m[withPad - 1] = bits & 255;
    var w = new Uint32Array(64);
    for (var off = 0; off < withPad; off += 64) {
      for (var i = 0; i < 16; i++)
        w[i] = (m[off+4*i] << 24) | (m[off+4*i+1] << 16) | (m[off+4*i+2] << 8) | m[off+4*i+3];
      for (i = 16; i < 64; i++) {
        var g0 = w[i-15], g1 = w[i-2];
        var s0 = ((g0 >>> 7) | (g0 << 25)) ^ ((g0 >>> 18) | (g0 << 14)) ^ (g0 >>> 3);
        var s1 = ((g1 >>> 17) | (g1 << 15)) ^ ((g1 >>> 19) | (g1 << 13)) ^ (g1 >>> 10);
        w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
      }
      var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (i = 0; i < 64; i++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) >>> 0;
        h=g; g=f; f=e; e=(d + t1) >>> 0; d=c; c=b; b=a; a=(t1 + t2) >>> 0;
      }
      H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 8; i++) {
      out[4*i]   = (H[i] >>> 24) & 255; out[4*i+1] = (H[i] >>> 16) & 255;
      out[4*i+2] = (H[i] >>> 8) & 255;  out[4*i+3] = H[i] & 255;
    }
    return out;
  }
  function hash256(b) { return sha256(sha256(b)); }

  /* Just enough of Core's serialization for these two hashes. */
  function ser() {
    var buf = [];
    var self = {
      raw: function (b) { for (var i = 0; i < b.length; i++) buf.push(b[i]); return self; },
      u8:  function (v) { buf.push(v & 255); return self; },
      i32: function (v) { for (var i = 0; i < 4; i++) buf.push((v >>> (8 * i)) & 255); return self; },
      /* uint64 little-endian; every value passed here is small */
      u64: function (v) { for (var i = 0; i < 4; i++) buf.push((v >>> (8 * i)) & 255);
                          for (i = 0; i < 4; i++) buf.push(0); return self; },
      /* CompactSize-prefixed vector; the two vectors hashed here are always < 253 bytes */
      vec: function (b) { buf.push(b.length); return self.raw(b); },
      out: function () { return new Uint8Array(buf); }
    };
    return self;
  }

  function keyBytes(nKey) {
    if (nKey && nKey.length === 32 && typeof nKey !== 'string') return nKey;
    if (typeof nKey !== 'string' || nKey.length !== 64) return null;
    var o = new Uint8Array(32);
    for (var i = 0; i < 32; i++) o[i] = parseInt(nKey.substr(2 * i, 2), 16);
    return o;
  }

  /* NetGroupManager::GetGroup with no asmap, as raw bytes. netGroup() above returns
   * the same grouping as a display key; this returns what actually gets hashed. */
  function groupBytes(network, b) {
    if (!b || !b.length) return null;
    if (network === 'ipv4' && b.length === 4) return new Uint8Array([1, b[0], b[1]]);
    if ((network === 'ipv6' || network === 'cjdns') && b.length === 16) {
      if (network === 'cjdns') return new Uint8Array([5, b[0], b[1] | 0x0f]);
      var li = linkedIPv4(b);
      if (li) return new Uint8Array([1, li[0], li[1]]);
      if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x04 && b[3] === 0x70)   /* he.net /36 */
        return new Uint8Array([2, b[0], b[1], b[2], b[3], b[4] | 0x0f]);
      return new Uint8Array([2, b[0], b[1], b[2], b[3]]);                     /* /32 */
    }
    if (network === 'onion' && b.length === 32) return new Uint8Array([3, b[0] | 0x0f]);
    if (network === 'i2p'   && b.length === 32) return new Uint8Array([4, b[0] | 0x0f]);
    return null;
  }

  /* CService::GetKey — GetAddrBytes() with the port appended big-endian.
   * GetAddrBytes() is NOT the raw address: for the v1-compatible networks it returns
   * the 16-byte v1 serialization, so an IPv4 address is hashed as ::ffff:a.b.c.d, 18
   * bytes in total rather than 6. IPv6 and CJDNS are 16 either way; onion v3 and I2P
   * are not v1-compatible and stay at their raw 32. */
  var IPV4_IN_IPV6_PREFIX = [0,0,0,0,0,0,0,0,0,0,0xFF,0xFF];
  function serviceKey(network, b, port) {
    var addr = b;
    if (network === 'ipv4' && b.length === 4) {
      addr = new Uint8Array(16);
      addr.set(IPV4_IN_IPV6_PREFIX, 0);
      addr.set(b, 12);
    }
    var k = new Uint8Array(addr.length + 2);
    k.set(addr, 0);
    k[addr.length] = (port >> 8) & 255;
    k[addr.length + 1] = port & 255;
    return k;
  }

  var TRIED_BUCKETS_PER_GROUP = 8, TRIED_BUCKET_COUNT = 256, BUCKET_SIZE = 64;

  function triedBucket(nKey, network, b, port) {
    var key = keyBytes(nKey), g = groupBytes(network, b);
    if (!key || !g) return -1;
    var h1 = hash256(ser().raw(key).vec(serviceKey(network, b, port)).out());
    var h2 = hash256(ser().raw(key).vec(g).u64(h1[0] % TRIED_BUCKETS_PER_GROUP).out());
    return h2[0] % TRIED_BUCKET_COUNT;              /* both moduli are powers of two */
  }

  function bucketPosition(nKey, fNew, bucket, network, b, port) {
    var key = keyBytes(nKey);
    if (!key || !b || !b.length) return -1;
    var h = hash256(ser().raw(key).u8(fNew ? 0x4e : 0x4b)      /* 'N' : 'K' */
                          .i32(bucket).vec(serviceKey(network, b, port)).out());
    return h[0] % BUCKET_SIZE;
  }

  root.PeersDat = { parse: parsePeersDat, sha3_256: sha3_256, base32: base32,
                    ipv6: ipv6, onionV3: onionV3,
                    netGroup: netGroup, addrBytes: addrBytes,
                    sha256: sha256, hash256: hash256, groupBytes: groupBytes,
                    triedBucket: triedBucket, bucketPosition: bucketPosition };
})(typeof globalThis !== 'undefined' ? globalThis : this);
