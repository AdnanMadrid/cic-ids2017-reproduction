# ================================================================
#  CIC-format flow dataset from YOUR pcap  —  Google Colab
#  Pure-Python (dpkt). No tcpdump/libpcap/Java — nothing to break.
#  Produces ~68 CIC-named features + Label, with your REAL data.
#
#  USE: paste each CELL into its own Colab cell, run top to bottom.
#       Upload dataset__2_.pcap in CELL 2. CELL 4 downloads the CSV.
# ================================================================


# ===== CELL 1 : install dpkt =====
!pip -q install dpkt pandas
print("ready")


# ===== CELL 2 : upload your pcap =====
from google.colab import files
print("Choose your pcap (dataset__2_.pcap / dataset (2).pcap)")
up = files.upload()
PCAP = list(up.keys())[0]
print("uploaded:", PCAP)


# ===== CELL 3 : extract flows + features + label  (this is the whole engine) =====
import dpkt, socket, statistics, csv, datetime
from collections import Counter

ATTACKER = "205.174.165.73"     # your Kali
# attack phase windows in minutes from capture start (measured from your traffic):
#   Brute Force 5-25, XSS 30-40, SQLi 45-52
OUT = "thursday_full_cicformat.csv"

def ip2s(b):
    try: return socket.inet_ntoa(b)
    except: return None
def key_norm(s,sp,d,dp,p):
    a=(s,sp); b=(d,dp)
    return ((s,sp,d,dp,p),True) if a<=b else ((d,dp,s,sp,p),False)

flows_active={}; finished=[]
def new_flow(k,ts):
    return dict(src=k[0],sport=k[1],dst=k[2],dport=k[3],proto=k[4],start=ts,last=ts,
        fpk=0,bpk=0,fby=0,bby=0,flen=[],blen=[],alen=[],ftimes=[],btimes=[],times=[],
        fhl=0,bhl=0,fpsh=0,bpsh=0,furg=0,burg=0,syn=0,ackf=0,psh=0,fin=0,rst=0,urg=0,
        ece=0,cwr=0,fwin=-1,bwin=-1,factdata=0,fminseg=0)

with open(PCAP,'rb') as f:
    for ts,buf in dpkt.pcap.Reader(f):
        try: eth=dpkt.ethernet.Ethernet(buf)
        except: continue
        ip=eth.data
        if not isinstance(ip,dpkt.ip.IP): continue
        s=ip2s(ip.src); d=ip2s(ip.dst); proto=ip.p
        if isinstance(ip.data,dpkt.tcp.TCP):
            tcp=ip.data; sp=tcp.sport; dp=tcp.dport; payload=len(tcp.data); flags=tcp.flags
            hl=tcp.off*4; win=tcp.win
            is_syn=(flags&0x02) and not (flags&0x10); is_end=(flags&0x01) or (flags&0x04)
        elif isinstance(ip.data,dpkt.udp.UDP):
            udp=ip.data; sp=udp.sport; dp=udp.dport; payload=len(udp.data)
            flags=0; hl=8; win=-1; is_syn=False; is_end=False
        else: continue
        k,fwd=key_norm(s,sp,d,dp,proto)
        fl=flows_active.get(k)
        if fl is None or (proto==6 and is_syn and fwd) or (ts-fl['last']>120.0):
            if fl is not None: finished.append(fl)
            fl=new_flow(k,ts); flows_active[k]=fl
            fl['fminseg']=hl
        fl['last']=ts; fl['times'].append(ts); fl['alen'].append(payload)
        if fwd:
            fl['fpk']+=1; fl['fby']+=payload; fl['flen'].append(payload); fl['ftimes'].append(ts); fl['fhl']+=hl
            if payload>0: fl['factdata']+=1
            if fl['fwin']<0 and win>=0: fl['fwin']=win
        else:
            fl['bpk']+=1; fl['bby']+=payload; fl['blen'].append(payload); fl['btimes'].append(ts); fl['bhl']+=hl
            if fl['bwin']<0 and win>=0: fl['bwin']=win
        if proto==6:
            if flags&0x02: fl['syn']+=1
            if flags&0x10: fl['ackf']+=1
            if flags&0x08:
                fl['psh']+=1
                fl['fpsh' if fwd else 'bpsh']+=1
            if flags&0x01: fl['fin']+=1
            if flags&0x04: fl['rst']+=1
            if flags&0x20:
                fl['urg']+=1; fl['furg' if fwd else 'burg']+=1
            if flags&0x40: fl['ece']+=1
            if flags&0x80: fl['cwr']+=1
        if proto==6 and is_end:
            finished.append(fl); flows_active.pop(k,None)
finished.extend(flows_active.values()); order=finished

def st(xs):
    if not xs: return (0,0,0,0)
    if len(xs)==1: return (max(xs),min(xs),xs[0],0)
    return (max(xs),min(xs),statistics.mean(xs),statistics.pstdev(xs))
def iat(t):
    if len(t)<2: return (0,0,0,0,0)
    d=[(t[i+1]-t[i])*1e6 for i in range(len(t)-1)]
    return (sum(d),max(d),min(d),statistics.mean(d),statistics.pstdev(d))

base=min(fl['start'] for fl in order)
def label(fl):
    if ATTACKER not in (fl['src'],fl['dst']): return "BENIGN"
    if 80 not in (fl['sport'],fl['dport']): return "BENIGN"
    m=(fl['start']-base)/60.0
    if 4.5<=m<25.5:  return "Web Attack  Brute Force"
    if 29.5<=m<40.5: return "Web Attack  XSS"
    if 44.5<=m<53.5: return "Web Attack  Sql Injection"
    return "BENIGN"

cols=["Flow ID","Source IP","Source Port","Destination IP","Destination Port","Protocol","Timestamp",
"Flow Duration","Total Fwd Packets","Total Backward Packets","Total Length of Fwd Packets","Total Length of Bwd Packets",
"Fwd Packet Length Max","Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std",
"Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std",
"Flow Bytes/s","Flow Packets/s","Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min",
"Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min",
"Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min",
"Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags","Fwd Header Length","Bwd Header Length",
"Fwd Packets/s","Bwd Packets/s","Min Packet Length","Max Packet Length","Packet Length Mean","Packet Length Std","Packet Length Variance",
"FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count","URG Flag Count","CWE Flag Count","ECE Flag Count",
"Down/Up Ratio","Average Packet Size","Avg Fwd Segment Size","Avg Bwd Segment Size",
"Subflow Fwd Packets","Subflow Fwd Bytes","Subflow Bwd Packets","Subflow Bwd Bytes",
"Init_Win_bytes_forward","Init_Win_bytes_backward","act_data_pkt_fwd","min_seg_size_forward","Label"]

with open(OUT,"w",newline="") as out:
    w=csv.writer(out); w.writerow(cols); lab=Counter()
    for fl in order:
        dur=fl['last']-fl['start']; dur_us=dur*1e6
        fmax,fmin,fmean,fstd=st(fl['flen']); bmax,bmin,bmean,bstd=st(fl['blen'])
        pmax,pmin,pmean,pstd=st(fl['alen']); pvar=pstd*pstd
        fit,fimax,fimin,fimean,fistd=iat(fl['ftimes']); bit,bimax,bimin,bimean,bistd=iat(fl['btimes'])
        _,aimax,aimin,aimean,aistd=iat(sorted(fl['times']))
        totpk=fl['fpk']+fl['bpk']; totby=fl['fby']+fl['bby']
        bps=(totby/dur) if dur>0 else 0; pps=(totpk/dur) if dur>0 else 0
        fpps=(fl['fpk']/dur) if dur>0 else 0; bpps=(fl['bpk']/dur) if dur>0 else 0
        downup=(fl['bpk']/fl['fpk']) if fl['fpk']>0 else 0
        avgpk=(totby/totpk) if totpk>0 else 0
        afseg=(fl['fby']/fl['fpk']) if fl['fpk']>0 else 0
        abseg=(fl['bby']/fl['bpk']) if fl['bpk']>0 else 0
        lb=label(fl); lab[lb]+=1
        tstr=datetime.datetime.fromtimestamp(fl['start'],datetime.timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
        w.writerow([f"{fl['src']}-{fl['dst']}-{fl['sport']}-{fl['dport']}-{fl['proto']}",
        fl['src'],fl['sport'],fl['dst'],fl['dport'],fl['proto'],tstr,
        round(dur_us),fl['fpk'],fl['bpk'],fl['fby'],fl['bby'],
        fmax,fmin,round(fmean,2),round(fstd,2),bmax,bmin,round(bmean,2),round(bstd,2),
        round(bps,2),round(pps,2),round(aimean,1),round(aistd,1),round(aimax,1),round(aimin,1),
        round(fit,1),round(fimean,1),round(fistd,1),round(fimax,1),round(fimin,1),
        round(bit,1),round(bimean,1),round(bistd,1),round(bimax,1),round(bimin,1),
        fl['fpsh'],fl['bpsh'],fl['furg'],fl['burg'],fl['fhl'],fl['bhl'],
        round(fpps,2),round(bpps,2),pmin,pmax,round(pmean,2),round(pstd,2),round(pvar,2),
        fl['fin'],fl['syn'],fl['rst'],fl['psh'],fl['ackf'],fl['urg'],fl['cwr'],fl['ece'],
        round(downup,2),round(avgpk,2),round(afseg,2),round(abseg,2),
        fl['fpk'],fl['fby'],fl['bpk'],fl['bby'],
        fl['fwin'],fl['bwin'],fl['factdata'],fl['fminseg'],lb])

print("flows:",len(order)," columns:",len(cols))
print("labels:")
for k,v in lab.most_common(): print(f"  {v:>7} {k}")


# ===== CELL 4 : quick look + download =====
import pandas as pd
df=pd.read_csv("thursday_full_cicformat.csv")
print(df["Label"].value_counts())
print("shape:",df.shape)
from google.colab import files
files.download("thursday_full_cicformat.csv")
