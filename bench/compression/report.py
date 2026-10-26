#!/usr/bin/env python3
"""Validate cross-runtime frames and create an interactive benchmark report."""
import argparse
import csv
import html
import json
from pathlib import Path
import sys

from benchmark import codec


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run")
    parser.add_argument("destination")
    args = parser.parse_args()
    run, destination = Path(args.run), Path(args.destination)
    destination.mkdir(parents=True, exist_ok=True)
    native = json.loads((run/"native-results.json").read_text())
    go = json.loads((run/"go-results.json").read_text())
    http = json.loads((run/"http-results.json").read_text())
    memory = json.loads((run/"memory-results.json").read_text())
    rows = native["results"] + go["results"]
    assert len(native["results"]) == 285 and len(go["results"]) == 450
    assert len(http["results"]) == 48 and len(memory["results"]) == 8
    assert all(r["roundtrip"] for r in rows + http["results"])
    assert all(r["encode"]["samples"] >= 3 and r["decode"]["samples"] >= 9 for r in rows)
    crossed = 0
    for item in native["corpora"]:
        data = Path(item["path"]).read_bytes()
        for frame in (run/"cross-decode"/item["name"]).glob("*.bin"):
            name = "brotli" if frame.name.startswith("brotli") else "zstd"
            _, decode = codec(name, 1, len(data), b"")
            assert decode(frame.read_bytes()) == data, str(frame)
            crossed += 1
    assert crossed == 330, crossed
    validation = {"codec_cases": len(rows), "http_cases": len(http["results"]),
                  "http_requests": sum(r["requests"] for r in http["results"]),
                  "retained_memory_cases": len(memory["results"]),
                  "go_frames_decoded_by_native_libraries": crossed,
                  "all_roundtrips_match": True}
    (run/"validation.json").write_text(json.dumps(validation, indent=2)+"\n")
    corpora = [{k:v for k,v in c.items() if k != "path"} for c in native["corpora"]]
    data = {"metadata": native["metadata"], "go": {k:v for k,v in go.items() if k != "results"},
            "corpora": corpora, "results": rows, "http": http, "memory": memory,
            "validation": validation}
    stem = "2026-10-26-compression"
    (destination/(stem+".json")).write_text(json.dumps(data, indent=2)+"\n")
    fields = ["corpus","kind","codec","level","input_bytes","compressed_bytes","remaining_percent",
              "encode_median_ms","encode_p95_ms","decode_median_ms","decode_p95_ms",
              "encode_samples","decode_samples","encode_allocated_bytes_per_op","peak_rss_kib"]
    with (destination/(stem+".csv")).open("w") as f:
        writer=csv.DictWriter(f,fieldnames=fields,lineterminator="\n");writer.writeheader()
        for r in rows:
            writer.writerow({**{k:r[k] for k in fields[:6]},
                "remaining_percent":100*r["compressed_bytes"]/r["input_bytes"],
                "encode_median_ms":r["encode"]["median_ms"],"encode_p95_ms":r["encode"]["p95_ms"],
                "decode_median_ms":r["decode"]["median_ms"],"decode_p95_ms":r["decode"]["p95_ms"],
                "encode_samples":r["encode"]["samples"],"decode_samples":r["decode"]["samples"],
                "encode_allocated_bytes_per_op":r["encode"].get("allocated_bytes_per_op",""),
                "peak_rss_kib":r.get("peak_rss_kib","")})
    def selected(corpus, name, level):
        return next(r for r in rows if r["corpus"]==corpus and r["codec"]==name and r["level"]==level)
    profiles=[("gzip-go-fresh",1,"gzip 1 · current"),("gzip-go-reuse",1,"gzip 1 · reuse"),
              ("zstd-go-entropy-reuse",1,"Zstd fastest · entropy"),
              ("zstd-go-entropy-reuse",3,"Zstd default · entropy"),("brotli-go-reuse",4,"Brotli 4 · reuse")]
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes=plt.subplots(2,2,figsize=(12,8),layout="constrained")
    colors=["#777777","#aaaaaa","#17655e","#52867c","#3c3c3c"]
    for axis, corpus in zip(axes[0],("page-medium","page-large")):
        rs=[selected(corpus,name,level) for name,level,_ in profiles]
        for r,(_,_,label),color in zip(rs,profiles,colors):
            axis.scatter(r["encode"]["median_ms"],100*r["compressed_bytes"]/r["input_bytes"],s=45,color=color,label=label)
        axis.set_xscale("log");axis.set_xlabel("Median encoder time (ms, logarithmic)")
        axis.set_ylabel("Wire bytes remaining (% of original)")
        axis.set_title(f'{corpus}: {rs[0]["input_bytes"]/1048576:.2f} MiB input')
        axis.grid(alpha=.15)
    axes[0,0].legend(fontsize=8,loc="best")
    h=[r for r in http["results"] if r["corpus"]=="page-large" and r["concurrency"]==1 and r["profile"] in
       ("gzip-1-fresh","gzip-1-reuse","zstd-1-entropy-reuse","zstd-3-entropy-reuse","brotli-4-reuse")]
    axes[1,0].barh([r["profile"] for r in h],[r["median_ms"] for r in h],color=colors)
    axes[1,0].set_xlabel("Median completion time (ms, includes decoding)")
    axes[1,0].set_ylabel("Server compression profile")
    axes[1,0].set_title("Large-page private loopback HTTP · one active request")
    m=[r for r in memory["results"] if r["retained_writers"]==4]
    axes[1,1].barh([r["profile"] for r in m],[r["retained_heap_bytes"]/1048576 for r in m],color=[colors[i] for i in (0,2,3,4)])
    axes[1,1].set_xlabel("Retained Go heap for four writers (MiB)")
    axes[1,1].set_ylabel("Reusable encoder profile")
    axes[1,1].set_title("Encoder pool memory after GC · 1 MiB Zstd window")
    fig.suptitle("Daochi compression · synthetic workloads · 26 October 2026",fontsize=15)
    fig.text(.5,-.025,"Local measurements · AMD Ryzen 9 9950X · Go 1.26.10 · one codec worker · not a production or phone benchmark",ha="center",fontsize=9)
    fig.savefig(destination/(stem+".png"),dpi=160,bbox_inches="tight");plt.close(fig)
    medium=selected("page-medium","gzip-go-fresh",1)
    zmedium=selected("page-medium","zstd-go-entropy-reuse",1)
    largeh={r["profile"]:r for r in h}
    identity=selected("pair-identity","gzip-go-fresh",1)
    packed=selected("pair-packed","gzip-go-fresh",1)
    summary={"validation":validation,
        "medium_page":{"input_bytes":medium["input_bytes"],"gzip_bytes":medium["compressed_bytes"],"zstd_bytes":zmedium["compressed_bytes"],
                       "gzip_encode_ms":medium["encode"]["median_ms"],"zstd_encode_ms":zmedium["encode"]["median_ms"]},
        "large_loopback_ms":{"gzip":largeh["gzip-1-fresh"]["median_ms"],"zstd":largeh["zstd-1-entropy-reuse"]["median_ms"]},
        "packed_records_wire_saving_percent":100*(1-packed["compressed_bytes"]/identity["compressed_bytes"])}
    (run/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    template = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Daochi compression benchmark — 26 October 2026</title>
<style>body{font:16px/1.55 system-ui,sans-serif;margin:0;background:#fafaf8;color:#202723}main{box-sizing:border-box;max-width:1240px;margin:auto;padding:32px}h1{font-size:30px;line-height:1.2}h2{margin-top:36px}a{color:#17655e}small,.note{color:#5d665f}section{border-top:1px solid #d7ddd7;padding-top:16px;margin-top:26px}.lead{font-size:20px;max-width:900px}.metrics{display:flex;gap:36px;flex-wrap:wrap;margin:28px 0}.metrics strong{font-size:28px;display:block;color:#17655e}label{display:inline-flex;flex-direction:column;vertical-align:top;width:min(260px,100%);margin:0 18px 14px 0}select{padding:7px;font:inherit;max-width:100%}table{border-collapse:collapse;width:100%;font-size:14px}td,th{text-align:right;padding:8px;border-bottom:1px solid #ddd}td:first-child,th:first-child{text-align:left}th{background:#edf1eb;position:sticky;top:0}.scroll{overflow:auto}img{max-width:100%;height:auto}code{background:#edf1eb;padding:1px 4px}details{margin:16px 0}summary{cursor:pointer;font-weight:600}button{padding:7px 14px;font:inherit;border:1px solid #9aa79e;background:white;cursor:pointer}@media(max-width:650px){main{padding:18px}.metrics{gap:18px}h1{font-size:26px}}</style>
<main><small>Daochi · compression upgrade study · 26 October 2026</small><h1>Use Zstandard for negotiated sync responses.<br>Keep gzip for compatibility.</h1>
<p class="lead">The fastest practical HTTP candidate is reusable Go Zstandard in its fastest mode, with literal entropy compression explicitly enabled. Pre-encryption record packing delivers the larger bandwidth gain. These are local synthetic measurements; production rollout remains a separate gate.</p>
<div class="metrics"><div><strong id="case-count"></strong>codec cases; all roundtrips match</div><div><strong id="http-gain"></strong>faster large-page loopback completion</div><div><strong id="packing"></strong>fewer wire bytes with existing record packing</div></div>
<p><a href="../compression.md">Read the compression guide</a> · <a href="2026-10-26-compression.json">Raw JSON</a> · <a href="2026-10-26-compression.csv">CSV</a></p>
<img src="2026-10-26-compression.png" alt="Four plots compare encoder time, compressed response size, loopback completion time and retained encoder memory.">
<section><h2>What changes the decision</h2><ul><li>Default Go Zstandard can store large encrypted/base64 pages nearly uncompressed. The explicit <code>WithAllLitEntropyCompression(true)</code> option is required for this workload.</li><li>Brotli 11 offers a small extra saving on encrypted pages at a large CPU cost. LZ4 is fast but saves little on those pages and is not a standard browser HTTP content coding.</li><li>The current Go gzip encoder is much faster than zlib gzip at level 1. Algorithm names alone are insufficient; implementation and reuse matter.</li><li>Retain at most four idle encoder contexts initially. Four Zstandard fastest writers retain about 11.3 MiB of Go heap here, versus 4.6 MiB for gzip and 46.2 MiB for Brotli 4.</li></ul></section>
<section><h2>Explore all codec measurements</h2><label>Workload <select id="corpus"></select></label><label>Implementation <select id="runtime"><option value="go">Go server candidates</option><option value="native">Native/client codecs</option></select></label><label>Sort by <select id="sort"><option value="size">Compressed bytes</option><option value="encode">Encoder median</option><option value="decode">Decoder median</option></select></label><p id="corpus-description" class="note"></p><div class="scroll"><table><thead><tr><th>Profile</th><th>Wire bytes</th><th>Original left</th><th>Encode median / p95 (ms)</th><th>Decode median / p95 (ms)</th><th>Encode allocations (bytes/op)</th><th>Samples encode / decode</th></tr></thead><tbody id="codec-rows"></tbody></table></div></section>
<section><h2>Network completion model</h2><p class="note">Model, not a measured network: encoder median + payload bytes ÷ selected bandwidth + decoder median. Excludes HTTP headers, TLS, RTT, database work and streaming overlap. Both encode and decode use the selected implementation. Physical Moto, browser and low-power server timing are pending.</p><label>Bandwidth <select id="bandwidth"><option value="0.5">0.5 Mbps</option><option value="5" selected>5 Mbps</option><option value="50">50 Mbps</option><option value="500">500 Mbps</option></select></label><div class="scroll"><table><thead><tr><th>Profile</th><th>Sequential completion model (ms)</th><th>Payload transfer alone (ms)</th></tr></thead><tbody id="network-rows"></tbody></table></div></section>
<section><h2>Private loopback HTTP</h2><p class="note">24 measured requests per case after warmup; one Go worker, keepalive, no TLS, no database or signatures. Completion includes HTTP read, decompression and byte comparison. First response byte means response headers, not the first decoded record.</p><label>Workload <select id="http-corpus"><option>control</option><option selected>page-medium</option><option>page-large</option></select></label><label>Active requests <select id="concurrency"><option>1</option><option>4</option></select></label><div class="scroll"><table><thead><tr><th>Profile</th><th>Wire bytes</th><th>Median / p95 (ms)</th><th>First response byte median (ms)</th><th>Decoded throughput (MiB/s)</th><th>Allocated bytes/request</th></tr></thead><tbody id="http-rows"></tbody></table></div></section>
<section><h2>Memory and reproducibility</h2><div class="scroll"><table><thead><tr><th>Encoder</th><th>Retained writers</th><th>Retained heap (MiB)</th></tr></thead><tbody id="memory-rows"></tbody></table></div><p class="note">Heap is measured after GC, with the large page already resident and compressed output discarded. It excludes decoder buffers and the rest of the application. Native peak RSS includes the Python interpreter and inherited process high-water; small workspace differences cannot be inferred from its common floor.</p><details><summary>Method, versions and limitations</summary><p id="method"></p><p id="versions"></p><p>15 deterministic synthetic corpora, 228 bytes–4,058,818 bytes. Records use generated UTF-8 structured JSON, and simulated ciphertext uses uniform pseudorandom bytes. Real encrypted content is not inspected. The record packing pair starts from identical generated plaintext records; encryption is modeled by equal-length random bytes, so crypto CPU and nested-envelope overhead are excluded. Do not interpret the packing percentage as a forecast of user data.</p><p>A 16 KiB dictionary was trained on separate synthetic records with distinct IDs and a different seed; dictionary training and download cost are excluded from codec timing. Dictionary wins need amortization and a new negotiated record format.</p><p>Go Zstandard modes are library presets, approximately corresponding to native levels 1/3/7/11; levels are not directly comparable across libraries. Native bindings include allocation/copy overhead. Go reuse measurements keep output buffers warm; streaming HTTP and retained-memory measurements are separate. Empirical p95 with small sample counts is coarse, especially high-effort codecs. No phone energy, packet loss, target server, TLS or production tail latency has been measured. The benchmark run itself did not change or deploy production code; see the compression guide for current behavior.</p></details></section></main>
<script>const DATA=__DATA__;const SUMMARY=__SUMMARY__;
const $=id=>document.getElementById(id);const fmt=n=>Number(n).toLocaleString(undefined,{maximumFractionDigits:3});
const go=r=>r.codec.includes('-go-');
function current(){let rows=DATA.results.filter(r=>r.corpus===$('corpus').value&&go(r)===($('runtime').value==='go'));const key=$('sort').value;return rows.sort((a,b)=>key==='size'?a.compressed_bytes-b.compressed_bytes:a[key].median_ms-b[key].median_ms)}
function name(r){return r.codec+' / '+r.level}
function render(){const rows=current();const c=DATA.corpora.find(c=>c.name===$('corpus').value);$('corpus-description').textContent=c.description+' · '+fmt(c.bytes)+' input bytes · source: local synthetic benchmark, 26 October 2026';$('codec-rows').innerHTML=rows.map(r=>`<tr><td>${name(r)}</td><td>${fmt(r.compressed_bytes)}</td><td>${fmt(100*r.compressed_bytes/r.input_bytes)}%</td><td>${fmt(r.encode.median_ms)} / ${fmt(r.encode.p95_ms)}</td><td>${fmt(r.decode.median_ms)} / ${fmt(r.decode.p95_ms)}</td><td>${r.encode.allocated_bytes_per_op===undefined?'—':fmt(r.encode.allocated_bytes_per_op)}</td><td>${r.encode.samples} / ${r.decode.samples}</td></tr>`).join('');const rate=Number($('bandwidth').value);$('network-rows').innerHTML=rows.map(r=>({r,wire:8*r.compressed_bytes/(rate*1000)})).sort((a,b)=>(a.r.encode.median_ms+a.wire+a.r.decode.median_ms)-(b.r.encode.median_ms+b.wire+b.r.decode.median_ms)).map(({r,wire})=>`<tr><td>${name(r)}</td><td>${fmt(r.encode.median_ms+wire+r.decode.median_ms)}</td><td>${fmt(wire)}</td></tr>`).join('')}
function renderHTTP(){$('http-rows').innerHTML=DATA.http.results.filter(r=>r.corpus===$('http-corpus').value&&r.concurrency===Number($('concurrency').value)).sort((a,b)=>a.median_ms-b.median_ms).map(r=>`<tr><td>${r.profile}</td><td>${fmt(r.compressed_bytes)}</td><td>${fmt(r.median_ms)} / ${fmt(r.p95_ms)}</td><td>${fmt(r.first_response_byte_median_ms)}</td><td>${fmt(r.uncompressed_mib_per_second)}</td><td>${fmt(r.allocated_bytes_per_request)}</td></tr>`).join('')}
$('corpus').innerHTML=DATA.corpora.map(c=>`<option value="${c.name}">${c.name}</option>`).join('');$('corpus').value='page-medium';for(const id of ['corpus','runtime','sort','bandwidth'])$(id).addEventListener('change',render);for(const id of ['http-corpus','concurrency'])$(id).addEventListener('change',renderHTTP);
$('case-count').textContent=SUMMARY.validation.codec_cases;$('http-gain').textContent=fmt(SUMMARY.large_loopback_ms.gzip/SUMMARY.large_loopback_ms.zstd)+'×';$('packing').textContent=fmt(SUMMARY.packed_records_wire_saving_percent)+'%';$('memory-rows').innerHTML=DATA.memory.results.map(r=>`<tr><td>${r.profile}</td><td>${r.retained_writers}</td><td>${fmt(r.retained_heap_bytes/1048576)}</td></tr>`).join('');$('method').textContent=DATA.metadata.method;$('versions').textContent='Go '+DATA.go.go+'; '+DATA.go.zstd_module+'; '+DATA.go.brotli_module+'; native zlib '+DATA.metadata.zlib+', Zstd '+DATA.metadata.zstd+', Brotli '+DATA.metadata.brotli+', LZ4 '+DATA.metadata.lz4+'. CPU: '+DATA.metadata.cpu;render();renderHTTP();</script></html>'''
    # Keep source revisions in the saved receipt; avoid putting raw hashes in the visible report.
    visible_data=json.loads(json.dumps(data));visible_data["metadata"].pop("source_revision",None)
    output=template.replace("__DATA__",json.dumps(visible_data).replace("</","<\\/")).replace("__SUMMARY__",json.dumps(summary))
    (destination/(stem+".html")).write_text(output)
    print(json.dumps(summary,indent=2))


if __name__ == "__main__":
    main()
