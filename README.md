# CIC-IDS2017 Thursday-Morning Reproduction (CyberRange)

Reproduction of the CIC-IDS2017 Thursday-morning **Web Attacks** scenario
(Brute Force, XSS, SQL Injection) with benign background traffic, captured in
an Airbus CyberRange testbed and labelled in the CICFlowMeter feature format.

## Repository structure
```
cic-ids2017-reproduction/
├── README.md                         # this file
├── scripts/
│   ├── benign_linux.sh               # benign generator (Linux clients .17/.19/.25)
│   ├── benign_windows.ps1            # benign generator (Windows clients .5/.8/.9/.14/.15)
│   ├── attack.sh                     # attacker orchestration (Kali .73)
│   ├── capture.sh                    # SPAN capture (sensor .200)
│   └── label_flows.py                # offline labelling by attacker IP + time window
├── extraction/
│   └── CICFlow_Colab_FINAL.py        # pcap -> flow features (Colab, pure Python)
├── data/
│   ├── dataset__2_.pcap              # raw capture (ground truth)   [large - use Git LFS]
│   └── thursday_final_v2.csv         # labelled dataset (28,344 flows, 68 features)
├── analysis/
│   ├── Deep_Analysis.md              # feature-by-feature comparison vs CIC
│   └── Complete_Process_Analysis.md  # full process + timeline explanation
├── docs/
│   └── Overleaf_Implementation_Final.tex   # methodology & comparison write-up
└── presentation/
    └── CIC_Reproduction.pptx         # slide deck
```

## Host / IP plan
| Role | Host | IP |
|---|---|---|
| Attacker (Kali) | attacker-73 | 205.174.165.73 |
| Victim (DVWA) | web-server | 192.168.10.50 (public 205.174.165.68) |
| Services hub | ubuntu12-server | 192.168.10.51 |
| Benign clients (Linux) | client-17/19/25 | .17 .19 .25 |
| Benign clients (Windows) | client-05/08/09/14/15 | .5 .8 .9 .14 .15 |
| Capture (SPAN) | capture-sensor | 192.168.10.200 (iface enp9s0) |
| Firewall | pfSense | LAN 192.168.10.1 / WAN 205.174.165.80 |

## How to reproduce
1. Sync clocks (NTP) on all hosts.
2. Start capture on the sensor:            `sudo bash scripts/capture.sh`
3. Start benign on clients (60 min):       `sudo bash scripts/benign_linux.sh 60`
   (Windows: `powershell -ExecutionPolicy Bypass -File benign_windows.ps1 -RunMinutes 60`)
4. Start attacks on Kali:                  `sudo bash scripts/attack.sh 205.174.165.68`
5. Stop capture (Ctrl+C); keep `/tmp/attack_windows.log`.
6. Extract features + label:               run `extraction/CICFlow_Colab_FINAL.py` or
   `python scripts/label_flows.py flows.csv labeled.csv attack_windows.log`.

## Results (vs original CIC)
| Class | CIC | Ours |
|---|---|---|
| BENIGN | 168,186 | 26,322 |
| Brute Force | 1,507 | 808 (connections) |
| XSS | 652 | 774 (connections) |
| SQL Injection | 21 | ~11 (connections) |

Same attack ordering; victim `.50:80` matches CIC. Differences (attacker IP,
B-Profile substitute, protocol coverage, duration) are documented in `docs/`.

## Push to GitHub
```bash
cd cic-ids2017-reproduction
git init
git lfs install                    # for the large pcap
git lfs track "*.pcap"
git add .gitattributes
git add .
git commit -m "CIC-IDS2017 Thursday-morning reproduction: scripts, dataset, docs"
git branch -M main
git remote add origin https://github.com/<your-user>/cic-ids2017-reproduction.git
git push -u origin main
```
