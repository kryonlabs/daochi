#!/usr/bin/env python3
"""Reproducible, single-worker codec study; never reads account data.

Run with the managed desktop runner. Results and generated corpora belong in
the ignored build/scratch directory. No production codecs are changed.
"""
import argparse
import base64
import ctypes as C
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import resource
import statistics
import subprocess
import sys
import time
import zlib


def document(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def record(rng, index, target):
    words = ["practice", "breathing", "garden", "travel", "learning", "quiet",
             "morning", "balance", "family", "walking", "休息", "mañana"]
    obj = {"id": f"record-{index:06d}", "schema_version": 1,
           "updated_at": 1793000000 + index, "title": f"Session {index}",
           "duration_seconds": rng.randint(60, 7200),
           "tags": rng.sample(words, 3), "completed": bool(index % 3),
           "notes": "", "measurements": []}
    while len(document(obj)) < target:
        obj["notes"] += " ".join(rng.choices(words, k=18)) + ". "
        obj["measurements"].append({"at": len(obj["measurements"]),
                                    "value": round(rng.uniform(0, 100), 4)})
    return document(obj)


def page(rng, count, payload_size, packed=False, nested=False, structured=False):
    records = []
    for i in range(count):
        size = payload_size
        if structured:
            plain = record(random.Random(700000+i), i, payload_size)
            size = len(plain)
            if packed:
                size = len(zlib.compress(plain, level=1, wbits=31)) + 12
        sealed = rng.randbytes(size + 16)
        if nested:
            sealed = document({"profile": "daochi-record-v1", "key_id": "bench-key",
                               "alg": "xchacha20poly1305", "nonce": b64(rng.randbytes(24)),
                               "ciphertext": b64(sealed),
                               "aad": {"collection": "private.bench.v1.records", "id": str(i)}})
        records.append({"collection": "private.bench.v1.records", "id": f"record-{i:06d}",
                        "key_id": "bench-key", "nonce": b64(rng.randbytes(24)),
                        "ciphertext": b64(sealed), "updated_at": str(1793000000+i),
                        "schema_version": 1, "content_hash": hashlib.sha256(sealed).hexdigest()})
    return document({"protocol_version": 6, "status": "ok", "server_version": 200,
                     "server_clock": 1793000200, "encrypted_records_only": True,
                     "changes_complete": True, "min_supported_protocol": 1,
                     "latest_protocol": 6, "server_latest_protocol": 6,
                     "changes": {"habits": [], "habit_days": [], "sessions": [],
                                 "meditation_logs": [], "social_cache": [],
                                 "encrypted_records": records},
                     "applied": {"encrypted_records": count},
                     "server_capabilities": ["http-gzip-v1", "record-gzip-v1"]})


def corpus(out):
    rng = random.Random(20261026)
    items = []
    def add(name, kind, data, description):
        p = out / "corpus" / (name + ".bin")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        items.append({"name": name, "kind": kind, "path": str(p), "bytes": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(), "description": description})
    add("control", "control", document({"protocol_version":6, "app_id":"bench",
        "user_id_hash":"a"*64,"client_id":"synthetic-device","since_server_version":200,
        "encrypted_records_only":True,"record_limit":200}), "Small signed sync request body")
    for size in (512, 2048, 8192, 65536, 524288):
        add(f"record-{size}", "record", record(rng, size, size),
            "Synthetic UTF-8 structured JSON before encryption")
    add("page-small", "page", page(rng, 8, 512), "8 records, independent random ciphertext in base64url")
    add("page-medium", "page", page(rng, 64, 3072), "64 records, independent random ciphertext in base64url")
    add("page-large", "page", page(rng, 200, 15000), "200 records, near the 4 MiB page ciphertext bound")
    add("page-nested", "page", page(rng, 64, 3072, nested=True), "64 base64url envelopes containing base64url ciphertext")
    # Equal plaintext workload, two wire representations; these remain synthetic ciphertext.
    pair_seed = 70823
    add("pair-identity", "paired-page", page(random.Random(pair_seed), 200, 2048, structured=True),
        "200 structured 2 KiB records, identity ciphertext representation")
    add("pair-packed", "paired-page", page(random.Random(pair_seed), 200, 2048, packed=True, structured=True),
        "Same-size structured workload packed with gzip-1 before simulated encryption")
    add("legacy-json", "legacy", document({"protocol_version":5,"status":"ok",
        "data":{"sessions":[json.loads(record(rng, i, 2048)) for i in range(400)]}}),
        "Legacy typed JSON response, 400 different synthetic records")
    add("sealed-binary", "binary", rng.randbytes(262144), "Uniform bytes modeling encrypted media; negative control")
    add("compressed-media", "binary", zlib.compress(rng.randbytes(262144), 6),
        "Already-compressed incompressible bytes; negative control")
    # Training and evaluation use independent seeds and disjoint record IDs.
    train_rng = random.Random(913)
    samples = [record(train_rng, i+100000, 2048) for i in range(256)]
    lib = zstd_lib()
    sizes = (C.c_size_t * len(samples))(*map(len, samples))
    joined = b"".join(samples)
    dst = C.create_string_buffer(16384)
    n = lib.ZDICT_trainFromBuffer(dst, len(dst), joined, sizes, len(samples))
    zcheck(lib, n)
    (out / "public-synthetic.dict").write_bytes(dst.raw[:n])
    (out / "corpus.json").write_text(json.dumps(items, indent=2)+"\n")
    return items


def zstd_lib():
    lib = C.CDLL(ctypes.util.find_library("zstd"))
    for name, restype, args in [
        ("ZSTD_compressBound", C.c_size_t, [C.c_size_t]),
        ("ZSTD_compress", C.c_size_t, [C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_int]),
        ("ZSTD_decompress", C.c_size_t, [C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t]),
        ("ZSTD_isError", C.c_uint, [C.c_size_t]),
        ("ZSTD_getErrorName", C.c_char_p, [C.c_size_t]),
        ("ZSTD_versionString", C.c_char_p, []),
        ("ZSTD_createCCtx", C.c_void_p, []), ("ZSTD_createDCtx", C.c_void_p, []),
        ("ZSTD_freeCCtx", C.c_size_t, [C.c_void_p]), ("ZSTD_freeDCtx", C.c_size_t, [C.c_void_p]),
        ("ZSTD_compress_usingDict", C.c_size_t,[C.c_void_p,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_int]),
        ("ZSTD_decompress_usingDict", C.c_size_t,[C.c_void_p,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t,C.c_void_p,C.c_size_t]),
        ("ZDICT_trainFromBuffer", C.c_size_t,[C.c_void_p,C.c_size_t,C.c_void_p,C.POINTER(C.c_size_t),C.c_uint])]:
        fn = getattr(lib,name); fn.restype=restype; fn.argtypes=args
    return lib


def zcheck(lib, result):
    if lib.ZSTD_isError(result):
        raise RuntimeError(lib.ZSTD_getErrorName(result).decode())
    return result


def codec(name, level, n, dictionary):
    if name == "identity":
        return lambda b: bytes(memoryview(b)), lambda b: bytes(memoryview(b))
    if name == "gzip-zlib":
        return lambda b: zlib.compress(b, level=level, wbits=31), lambda b: zlib.decompress(b, wbits=31)
    if name == "brotli":
        import brotli
        return lambda b: brotli.compress(b, quality=level, lgwin=22), brotli.decompress
    if name == "lz4":
        import lz4.frame
        return lambda b: lz4.frame.compress(b, compression_level=level), lz4.frame.decompress
    lib = zstd_lib()
    # Fresh codec contexts, like the current per-request server gzip writer.
    # Buffers are included in measured calls, and outputs are copied to bytes.
    def compress(b):
        dst=C.create_string_buffer(lib.ZSTD_compressBound(len(b)))
        if name == "zstd-dict":
            ctx=lib.ZSTD_createCCtx()
            try: size=lib.ZSTD_compress_usingDict(ctx,dst,len(dst),b,len(b),dictionary,len(dictionary),level)
            finally: lib.ZSTD_freeCCtx(ctx)
        else: size=lib.ZSTD_compress(dst,len(dst),b,len(b),level)
        return dst.raw[:zcheck(lib,size)]
    def decompress(b):
        dst=C.create_string_buffer(n)
        if name == "zstd-dict":
            ctx=lib.ZSTD_createDCtx()
            try: size=lib.ZSTD_decompress_usingDict(ctx,dst,n,b,len(b),dictionary,len(dictionary))
            finally: lib.ZSTD_freeDCtx(ctx)
        else: size=lib.ZSTD_decompress(dst,n,b,len(b))
        return dst.raw[:zcheck(lib,size)]
    return compress,decompress


def timed(fn, value, minimum=9):
    samples=[]
    start=time.perf_counter()
    while len(samples)<minimum or (time.perf_counter()-start<0.045 and len(samples)<2000):
        at=time.perf_counter_ns(); result=fn(value)
        samples.append((time.perf_counter_ns()-at)/1e6)
        del result
    samples.sort()
    return {"median_ms":statistics.median(samples),
            "p95_ms":samples[min(len(samples)-1, int(len(samples)*.95))],
            "samples":len(samples)}


def worker(args):
    data=Path(args.input).read_bytes()
    dictionary=Path(args.dictionary).read_bytes()
    enc,dec=codec(args.codec,args.level,len(data),dictionary)
    encoded=enc(data)
    assert dec(encoded)==data, "roundtrip mismatch"
    # Every codec receives identical bytes; startup/import/dictionary training are outside timing.
    rss_before=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    minimum=3 if args.level>=11 and args.codec in ("brotli","zstd") else 9
    compressed=timed(enc,data,minimum)
    decoded=timed(dec,encoded)
    result={"codec":args.codec,"level":args.level,"input_bytes":len(data),
            "compressed_bytes":len(encoded),"encode":compressed,"decode":decoded,
            "peak_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            "rss_after_warmup_kib":rss_before,"roundtrip":True}
    print(json.dumps(result))


def main(args):
    out=Path(args.output).resolve(); out.mkdir(parents=True,exist_ok=True)
    items=corpus(out)
    meta={"date_utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
          "platform":platform.platform(),"python":sys.version,
          "cpu":next((s.split(':',1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')),'unknown'),
          "load_start":os.getloadavg(),"zlib":zlib.ZLIB_RUNTIME_VERSION,
          "zstd":zstd_lib().ZSTD_versionString().decode(),"worker_parallelism":1,
          "source_revision":subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
          "dictionary_bytes":(out/'public-synthetic.dict').stat().st_size,
          "dictionary_sha256":hashlib.sha256((out/'public-synthetic.dict').read_bytes()).hexdigest(),
          "method":"Independent sequential workers, fresh codec contexts, warmup roundtrip; >=9 samples and >=45ms per direction (>=3 samples for Brotli11/Zstd19); p95 is empirical, low-count estimates are coarse. Python/native bindings include buffer allocation and copies. RSS is whole worker high-water including interpreter, corpus and buffers, not codec workspace alone. Synthetic corpus, no account data or live network. 64-bit Ryzen desktop, not phone/server hardware."}
    import brotli,lz4
    meta.update(brotli=brotli.__version__,lz4=lz4.library_version_string())
    (out/'metadata.json').write_text(json.dumps(meta,indent=2)+'\n')
    configs=[('identity',0)]+[('gzip-zlib',n) for n in (1,3,6,9)]+[('zstd',n) for n in (-1,1,3,6,9,19)]+[('brotli',n) for n in (1,4,6,9,11)]+[('lz4',n) for n in (0,9)]+[('zstd-dict',3)]
    jobs=[(item,name,level) for item in items for name,level in configs]
    random.Random(42).shuffle(jobs)
    results=[]
    for index,(item,name,level) in enumerate(jobs):
        call=[sys.executable,__file__,'--worker','--input',item['path'],'--codec',name,
              '--level',str(level),'--dictionary',str(out/'public-synthetic.dict')]
        p=subprocess.run(call,capture_output=True,text=True,check=True,timeout=180)
        result=json.loads(p.stdout); result.update(corpus=item['name'],kind=item['kind'])
        results.append(result)
        (out/'native-results.json').write_text(json.dumps({'metadata':meta,'corpora':items,'results':results},indent=2)+'\n')
        if (index+1)%20==0: print(f'Completed {index+1}/{len(jobs)} native codec cases',flush=True)
    print(f'Completed {len(results)} native codec cases; all roundtrips verified',flush=True)


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--output'); p.add_argument('--worker',action='store_true')
    p.add_argument('--input'); p.add_argument('--codec'); p.add_argument('--level',type=int,default=1)
    p.add_argument('--dictionary')
    args=p.parse_args()
    worker(args) if args.worker else main(args)
