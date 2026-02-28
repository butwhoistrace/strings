package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/butwhoistrace/strings/internal"
	"github.com/butwhoistrace/strings/internal/threat"
)

func Generate(results []internal.StringResult, filePath string, sections []internal.SectionInfo, outputPath string) error {
	total := len(results)
	catCounts := make(map[string]int)
	for _, r := range results {
		for _, c := range r.Categories {
			catCounts[c]++
		}
	}
	sourceCounts := make(map[string]int)
	for _, r := range results {
		sourceCounts[r.Source]++
	}
	highEntropy := 0
	suspicious := 0
	for _, r := range results {
		if r.Entropy >= 4.5 {
			highEntropy++
		}
		if r.SuspiciousGroup != "" {
			suspicious++
		}
	}

	t := threat.Assess(results)
	info, _ := os.Stat(filePath)
	fileSize := info.Size()
	fileName := filepath.Base(filePath)
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	type jsonEntry struct {
		Value    string   `json:"value"`
		Offset   int64    `json:"offset"`
		Encoding string   `json:"encoding"`
		Section  string   `json:"section"`
		Cats     []string `json:"categories"`
		Entropy  float64  `json:"entropy"`
		EntLabel string   `json:"entropy_label"`
		APIGroup string   `json:"api_group"`
		Source   string   `json:"source"`
		XorKey   byte     `json:"xor_key"`
		Length   int      `json:"length"`
	}

	entries := make([]jsonEntry, len(results))
	for i, r := range results {
		val := r.Value
		if len(val) > 500 {
			val = val[:500]
		}
		entries[i] = jsonEntry{
			Value: val, Offset: r.Offset, Encoding: r.Encoding,
			Section: r.Section, Cats: r.Categories, Entropy: r.Entropy,
			EntLabel: r.EntropyLabel, APIGroup: r.SuspiciousGroup,
			Source: r.Source, XorKey: r.XorKey, Length: r.Length,
		}
	}

	resultsJSON, _ := json.Marshal(entries)
	_, _ = json.Marshal(sections)

	levelColor := map[string]string{"LOW": "#30a46c", "MEDIUM": "#f5d90a", "HIGH": "#e5484d", "CRITICAL": "#e5484d"}[t.Level]

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintf(f, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>strings | %s</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Outfit:wght@300;400;500;600;700&display=swap');
:root{--bg:#0a0a0b;--s1:#111113;--s2:#19191d;--s3:#222228;--b:#2a2a32;--bl:#35353f;--t:#e8e8ed;--td:#8888a0;--tm:#55556a;--a:#6e56cf;--ad:#4a3a8a;--r:#e5484d;--rd:#3a1d1f;--o:#f76808;--od:#3a2010;--g:#30a46c;--gd:#132d21;--bl2:#3b82f6;--bld:#172554;--y:#f5d90a;--yd:#3a3005;--c:#05c8c8;--cd:#0a2e2e;--p:#e93d82;--pd:#3a1428;--rad:8px;--radl:12px}
*{margin:0;padding:0;box-sizing:border-box}body{background:var(--bg);color:var(--t);font-family:'Outfit',sans-serif;font-weight:400;line-height:1.6;min-height:100vh}
.hdr{border-bottom:1px solid var(--b);padding:24px 32px;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}.hdr-l{display:flex;align-items:center;gap:14px}.logo{font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;color:var(--a);background:var(--s2);border:1px solid var(--b);border-radius:6px;padding:5px 10px;letter-spacing:.5px}.fi{display:flex;flex-direction:column;gap:1px}.fn{font-size:18px;font-weight:600;letter-spacing:-.3px}.fm{font-size:12px;color:var(--td);font-family:'JetBrains Mono',monospace}.hdr-r{display:flex;gap:6px;align-items:center}.hdr-r button{background:var(--s2);border:1px solid var(--b);color:var(--td);font-family:'Outfit',sans-serif;font-size:12px;padding:7px 14px;border-radius:var(--rad);cursor:pointer;transition:all .15s}.hdr-r button:hover{background:var(--s3);color:var(--t)}.threat-badge{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;padding:5px 12px;border-radius:6px;letter-spacing:1px}
.sts{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1px;background:var(--b);border-bottom:1px solid var(--b)}.st{background:var(--s1);padding:16px 20px;display:flex;flex-direction:column;gap:3px}.sv{font-size:24px;font-weight:700;letter-spacing:-1px;font-variant-numeric:tabular-nums}.sl{font-size:10px;color:var(--tm);text-transform:uppercase;letter-spacing:1px;font-weight:500}
.mn{display:grid;grid-template-columns:240px 1fr;min-height:calc(100vh - 180px)}.sb{border-right:1px solid var(--b);padding:16px 0;overflow-y:auto;max-height:calc(100vh - 180px);position:sticky;top:0}.ss{padding:0 12px;margin-bottom:20px}.st2{font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:var(--tm);font-weight:600;margin-bottom:6px;padding:0 8px}.fb{display:flex;align-items:center;justify-content:space-between;width:100%%;padding:5px 8px;border:none;background:transparent;color:var(--td);font-family:'Outfit',sans-serif;font-size:12px;border-radius:5px;cursor:pointer;transition:all .12s;text-align:left}.fb:hover{background:var(--s2);color:var(--t)}.fb.ac{background:var(--ad);color:var(--t)}.fc{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--tm);background:var(--s2);padding:1px 5px;border-radius:3px}.fb.ac .fc{background:var(--a);color:white}.fd{width:7px;height:7px;border-radius:50%%;display:inline-block;margin-right:6px;flex-shrink:0}
.ct{padding:16px 20px;overflow-y:auto;max-height:calc(100vh - 180px)}.sbar{position:sticky;top:0;z-index:10;background:var(--bg);padding-bottom:12px}.si{width:100%%;padding:8px 14px 8px 36px;background:var(--s1);border:1px solid var(--b);border-radius:var(--rad);color:var(--t);font-family:'JetBrains Mono',monospace;font-size:12px;outline:none;transition:border-color .15s}.si:focus{border-color:var(--a)}.sic{position:absolute;left:12px;top:50%%;transform:translateY(-50%%);color:var(--tm);pointer-events:none}.rc{font-size:11px;color:var(--tm);margin-top:6px;font-family:'JetBrains Mono',monospace}
.tw{border:1px solid var(--b);border-radius:var(--radl);overflow:hidden;margin-top:6px}table{width:100%%;border-collapse:collapse;font-size:12px}th{background:var(--s2);padding:8px 12px;text-align:left;font-weight:500;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--tm);border-bottom:1px solid var(--b);position:sticky;top:0;cursor:pointer;user-select:none;white-space:nowrap}th:hover{color:var(--td)}th.so{color:var(--a)}td{padding:6px 12px;border-bottom:1px solid var(--b);vertical-align:top}tr:last-child td{border-bottom:none}tr:hover td{background:var(--s1)}
.sv2{font-family:'JetBrains Mono',monospace;font-size:11px;word-break:break-all;line-height:1.5;color:var(--t);max-width:550px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.sv2:hover{white-space:normal;overflow:visible}.mo{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--td)}
.tg{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:500;margin:1px 1px;white-space:nowrap}.tg-url{background:var(--bld);color:var(--bl2)}.tg-email{background:var(--cd);color:var(--c)}.tg-ipv4,.tg-ipv6{background:var(--od);color:var(--o)}.tg-domain{background:var(--bld);color:var(--bl2)}.tg-win_path,.tg-unix_path{background:var(--gd);color:var(--g)}.tg-registry{background:var(--yd);color:var(--y)}.tg-dll_api{background:var(--pd);color:var(--p)}.tg-error{background:var(--rd);color:var(--r)}.tg-crypto{background:var(--ad);color:var(--a)}.tg-base64_blob{background:var(--cd);color:var(--c)}.tg-hash_md5,.tg-hash_sha1,.tg-hash_sha256{background:var(--yd);color:var(--y)}.tg-credential,.tg-basic_auth,.tg-bearer_token{background:var(--rd);color:var(--r)}.tg-port{background:var(--cd);color:var(--c)}.tg-general{background:var(--s3);color:var(--tm)}.tg-raw{background:var(--s3);color:var(--tm)}.tg-base64{background:var(--cd);color:var(--c)}.tg-xor{background:var(--rd);color:var(--r)}
.eb{display:flex;align-items:center;gap:5px}.ef{height:3px;border-radius:2px;width:36px;background:var(--s3);overflow:hidden}.efi{height:100%%;border-radius:2px}.el{background:var(--g)}.en{background:var(--bl2)}.ee{background:var(--y)}.eh{background:var(--o)}.ev{background:var(--r)}.secb{font-family:'JetBrains Mono',monospace;font-size:10px;padding:1px 5px;border-radius:3px;background:var(--s3);color:var(--td)}
.pg{display:flex;align-items:center;justify-content:center;gap:6px;padding:14px 0}.pg button{background:var(--s2);border:1px solid var(--b);color:var(--td);font-family:'Outfit',sans-serif;font-size:12px;padding:5px 12px;border-radius:5px;cursor:pointer;transition:all .12s}.pg button:hover:not(:disabled){background:var(--s3);color:var(--t)}.pg button:disabled{opacity:.3;cursor:default}.pg .pi{font-size:12px;color:var(--tm);font-family:'JetBrains Mono',monospace}
@media(max-width:900px){.mn{grid-template-columns:1fr}.sb{border-right:none;border-bottom:1px solid var(--b);max-height:none;position:static}.ct{max-height:none}}
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--b);border-radius:3px}
</style>
</head>
<body>
<div class="hdr"><div class="hdr-l"><span class="logo">strings</span><div class="fi"><div class="fn">%s</div><div class="fm">%s &middot; %d sections &middot; %s</div></div></div><div class="hdr-r"><span class="threat-badge" style="background:%s22;color:%s;border:1px solid %s44">THREAT: %s (%d)</span><button onclick="xJSON()">JSON</button><button onclick="xCSV()">CSV</button></div></div>
<div class="sts"><div class="st"><div class="sv" style="color:var(--a)">%s</div><div class="sl">Total Strings</div></div><div class="st"><div class="sv" style="color:var(--o)">%d</div><div class="sl">High Entropy</div></div><div class="st"><div class="sv" style="color:var(--r)">%d</div><div class="sl">Suspicious APIs</div></div><div class="st"><div class="sv" style="color:var(--g)">%d</div><div class="sl">Base64 Decoded</div></div><div class="st"><div class="sv" style="color:var(--p)">%d</div><div class="sl">XOR Decrypted</div></div></div>
<div class="mn"><div class="sb" id="sb"><div class="ss"><div class="st2">Category</div><button class="fb ac" onclick="fC('all',this)"><span>All</span><span class="fc">%s</span></button></div><div class="ss"><div class="st2">Source</div><div id="sf"></div></div><div class="ss"><div class="st2">Encoding</div><div id="ef"></div></div><div class="ss"><div class="st2">Section</div><div id="scf"></div></div><div class="ss"><div class="st2">Entropy</div><div id="enf"></div></div></div>
<div class="ct"><div class="sbar" style="position:relative"><svg class="sic" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><input class="si" id="search" type="text" placeholder="Search strings..."><div class="rc" id="rc"></div></div><div class="tw"><table><thead><tr><th style="width:70px" onclick="sB('offset')" id="th-offset">Offset</th><th onclick="sB('value')" id="th-value">String</th><th style="width:80px" onclick="sB('encoding')" id="th-encoding">Enc</th><th style="width:70px" onclick="sB('section')" id="th-section">Section</th><th style="width:140px" onclick="sB('categories')" id="th-categories">Category</th><th style="width:95px" onclick="sB('entropy')" id="th-entropy">Entropy</th><th style="width:70px" onclick="sB('source')" id="th-source">Source</th></tr></thead><tbody id="tb"></tbody></table></div><div class="pg" id="pg"></div></div></div>
<script>
const D=%s;const PS=200;let F=[...D],P=1,sK='offset',sA=true,aF={c:'all',s:'all',e:'all',sc:'all',en:'all'};
const DC={'url':'var(--bl2)','email':'var(--c)','ipv4':'var(--o)','ipv6':'var(--o)','domain':'var(--bl2)','win_path':'var(--g)','unix_path':'var(--g)','registry':'var(--y)','dll_api':'var(--p)','error':'var(--r)','crypto':'var(--a)','base64_blob':'var(--c)','hash_md5':'var(--y)','hash_sha1':'var(--y)','hash_sha256':'var(--y)','credential':'var(--r)','basic_auth':'var(--r)','bearer_token':'var(--r)','port':'var(--c)','general':'var(--tm)'};
const EC={'low':'el','normal':'en','elevated':'ee','high':'eh','very high':'ev'};
function bF(){const cc={};D.forEach(r=>r.categories.forEach(x=>cc[x]=(cc[x]||0)+1));const cs=document.querySelector('.ss');Object.entries(cc).sort((a,b)=>b[1]-a[1]).forEach(([k,v])=>{const b=document.createElement('button');b.className='fb';b.innerHTML='<span><span class="fd" style="background:'+(DC[k]||'var(--tm)')+'"></span>'+k+'</span><span class="fc">'+v.toLocaleString()+'</span>';b.onclick=()=>fC(k,b);cs.appendChild(b)});
const sc={};D.forEach(r=>sc[r.source]=(sc[r.source]||0)+1);const se=document.getElementById('sf');aB(se,'all',D.length,'s','All',true);Object.entries(sc).sort((a,b)=>b[1]-a[1]).forEach(([k,v])=>aB(se,k,v,'s',k));
const ec={};D.forEach(r=>ec[r.encoding]=(ec[r.encoding]||0)+1);const ee=document.getElementById('ef');aB(ee,'all',D.length,'e','All',true);Object.entries(ec).sort((a,b)=>b[1]-a[1]).forEach(([k,v])=>aB(ee,k,v,'e',k));
const scc={};D.forEach(r=>scc[r.section||'(none)']=(scc[r.section||'(none)']||0)+1);const sce=document.getElementById('scf');aB(sce,'all',D.length,'sc','All',true);Object.entries(scc).sort((a,b)=>b[1]-a[1]).forEach(([k,v])=>aB(sce,k,v,'sc',k));
const enc={};D.forEach(r=>enc[r.entropy_label]=(enc[r.entropy_label]||0)+1);const ene=document.getElementById('enf');aB(ene,'all',D.length,'en','All',true);['low','normal','elevated','high','very high'].forEach(l=>{if(enc[l])aB(ene,l,enc[l],'en',l)})}
function aB(p,v,c,ft,l,a=false){const b=document.createElement('button');b.className='fb'+(a?' ac':'');b.innerHTML='<span>'+l+'</span><span class="fc">'+c.toLocaleString()+'</span>';b.onclick=()=>{p.querySelectorAll('.fb').forEach(x=>x.classList.remove('ac'));b.classList.add('ac');aF[ft]=v;aA()};p.appendChild(b)}
function fC(c,b){document.querySelector('.ss').querySelectorAll('.fb').forEach(x=>x.classList.remove('ac'));b.classList.add('ac');aF.c=c;aA()}
function aA(){const s=document.getElementById('search').value.toLowerCase();F=D.filter(r=>{if(aF.c!=='all'&&!r.categories.includes(aF.c))return false;if(aF.s!=='all'&&r.source!==aF.s)return false;if(aF.e!=='all'&&r.encoding!==aF.e)return false;if(aF.sc!=='all'&&(r.section||'(none)')!==aF.sc)return false;if(aF.en!=='all'&&r.entropy_label!==aF.en)return false;if(s&&!r.value.toLowerCase().includes(s))return false;return true});P=1;rT()}
function sB(k){if(sK===k)sA=!sA;else{sK=k;sA=true};document.querySelectorAll('th').forEach(t=>t.classList.remove('so'));document.getElementById('th-'+k)?.classList.add('so');F.sort((a,b)=>{let va=k==='categories'?a[k].join(','):a[k],vb=k==='categories'?b[k].join(','):b[k];if(typeof va==='string'){va=va.toLowerCase();vb=vb.toLowerCase()};if(va<vb)return sA?-1:1;if(va>vb)return sA?1:-1;return 0});rT()}
function eH(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
function rT(){const tp=Math.ceil(F.length/PS),st=(P-1)*PS,pg=F.slice(st,st+PS);document.getElementById('rc').textContent=F.length.toLocaleString()+' of '+D.length.toLocaleString()+' strings';document.getElementById('tb').innerHTML=pg.map(r=>'<tr><td class="mo">0x'+r.offset.toString(16).toUpperCase()+'</td><td><div class="sv2">'+eH(r.value)+'</div></td><td class="mo">'+r.encoding+'</td><td>'+(r.section?'<span class="secb">'+r.section+'</span>':'<span class="mo">-</span>')+'</td><td>'+r.categories.map(x=>'<span class="tg tg-'+x+'">'+x+'</span>').join('')+'</td><td><div class="eb"><div class="ef"><div class="efi '+EC[r.entropy_label]+'" style="width:'+Math.min(r.entropy/6*100,100)+'%%"></div></div><span class="mo">'+r.entropy+'</span></div></td><td><span class="tg tg-'+r.source+'">'+r.source+(r.source==='xor'?' 0x'+r.xor_key.toString(16).toUpperCase():'')+'</span></td></tr>').join('');const p=document.getElementById('pg');if(tp<=1){p.innerHTML='';return};p.innerHTML='<button '+(P===1?'disabled':'')+' onclick="gP('+(P-1)+')">&larr;</button><span class="pi">'+P+' / '+tp+'</span><button '+(P===tp?'disabled':'')+' onclick="gP('+(P+1)+')">&rarr;</button>'}
function gP(p){P=p;rT();document.querySelector('.ct').scrollTop=0}
document.getElementById('search').addEventListener('input',()=>aA());
function xJSON(){const b=new Blob([JSON.stringify(F,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='%s_strings.json';a.click()}
function xCSV(){let c='offset,encoding,section,categories,entropy,source,xor_key,value\n';F.forEach(r=>{c+=r.offset+','+r.encoding+','+r.section+',"'+r.categories.join(';')+'",'+r.entropy+','+r.source+','+r.xor_key+',"'+r.value.replace(/"/g,'""')+'"\n'});const b=new Blob([c],{type:'text/csv'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='%s_strings.csv';a.click()}
bF();rT();
</script></body></html>`,
		fileName, fileName, formatSize(fileSize), len(sections), timestamp,
		levelColor, levelColor, levelColor, t.Level, t.Score,
		formatNum(total), highEntropy, suspicious, sourceCounts["base64"], sourceCounts["xor"],
		formatNum(total),
		string(resultsJSON),
		fileName, fileName,
	)
	return nil
}

func formatSize(size int64) string {
	units := []string{"B", "KB", "MB", "GB"}
	s := float64(size)
	for _, u := range units {
		if s < 1024 {
			return fmt.Sprintf("%.1f %s", s, u)
		}
		s /= 1024
	}
	return fmt.Sprintf("%.1f TB", s)
}

func formatNum(n int) string {
	s := fmt.Sprintf("%d", n)
	if n < 1000 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
