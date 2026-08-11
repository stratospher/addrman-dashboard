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

  root.PeersDat = { parse: parsePeersDat, sha3_256: sha3_256, base32: base32,
                    ipv6: ipv6, onionV3: onionV3,
                    netGroup: netGroup, addrBytes: addrBytes };
})(typeof globalThis !== 'undefined' ? globalThis : this);
