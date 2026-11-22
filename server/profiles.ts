import type { DatasetProfile } from '../src/types/soc.js';

export const NETFLOW_40_FEATURES: string[] = [
  'L4_DST_PORT', 'PROTOCOL', 'L7_PROTO', 'IN_BYTES', 'IN_PKTS', 'OUT_BYTES', 'OUT_PKTS',
  'TCP_FLAGS', 'CLIENT_TCP_FLAGS', 'SERVER_TCP_FLAGS', 'FLOW_DURATION_MILLISECONDS',
  'DURATION_IN', 'DURATION_OUT', 'MIN_TTL', 'MAX_TTL', 'LONGEST_FLOW_PKT', 'SHORTEST_FLOW_PKT',
  'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN', 'SRC_TO_DST_SECOND_BYTES', 'DST_TO_SRC_SECOND_BYTES',
  'RETRANSMITTED_IN_BYTES', 'RETRANSMITTED_IN_PKTS', 'RETRANSMITTED_OUT_BYTES', 'RETRANSMITTED_OUT_PKTS',
  'SRC_TO_DST_AVG_THROUGHPUT', 'DST_TO_SRC_AVG_THROUGHPUT', 'NUM_PKTS_UP_TO_128_BYTES',
  'NUM_PKTS_128_TO_256_BYTES', 'NUM_PKTS_256_TO_512_BYTES', 'NUM_PKTS_512_TO_1024_BYTES',
  'NUM_PKTS_1024_TO_1514_BYTES', 'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT', 'ICMP_TYPE',
  'ICMP_IPV4_TYPE', 'DNS_QUERY_ID', 'DNS_QUERY_TYPE', 'DNS_TTL_ANSWER', 'FTP_COMMAND_RET_CODE',
];

export const CICIOT_46_FEATURES: string[] = [
  'flow_duration', 'Header_Length', 'Protocol Type', 'Duration', 'Rate', 'Srate', 'Drate',
  'fin_flag_number', 'syn_flag_number', 'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
  'ece_flag_number', 'cwr_flag_number', 'ack_count', 'syn_count', 'fin_count', 'urg_count',
  'rst_count', 'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP', 'UDP', 'DHCP',
  'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min', 'Max', 'AVG', 'Std', 'Tot size', 'IAT',
  'Number', 'Magnitue', 'Radius', 'Covariance', 'Variance', 'Weight',
];

function buildNBaiot115Features(): string[] {
  const windows = ['L5', 'L3', 'L1', 'L0.1', 'L0.01'];
  const feats: string[] = [];
  for (const w of windows) {
    feats.push(`MI_dir_${w}_weight`, `MI_dir_${w}_mean`, `MI_dir_${w}_variance`);
  }
  for (const w of windows) {
    feats.push(`H_${w}_weight`, `H_${w}_mean`, `H_${w}_variance`);
  }
  for (const w of windows) {
    feats.push(
      `HH_${w}_weight`, `HH_${w}_mean`, `HH_${w}_std`, `HH_${w}_magnitude`,
      `HH_${w}_radius`, `HH_${w}_covariance`, `HH_${w}_pcc`
    );
  }
  for (const w of windows) {
    feats.push(`HH_jit_${w}_weight`, `HH_jit_${w}_mean`, `HH_jit_${w}_variance`);
  }
  for (const w of windows) {
    feats.push(
      `HpHp_${w}_weight`, `HpHp_${w}_mean`, `HpHp_${w}_std`, `HpHp_${w}_magnitude`,
      `HpHp_${w}_radius`, `HpHp_${w}_covariance`, `HpHp_${w}_pcc`
    );
  }
  return feats; // exactly 15 + 15 + 35 + 15 + 35 = 115 features
}

export const NBAIOT_115_FEATURES: string[] = buildNBaiot115Features();

export const FEATURE_SEMANTICS: Record<string, string> = {
  IN_BYTES: 'Inbound source-to-destination byte volume (flooding or staged payload transfer)',
  OUT_BYTES: 'Outbound destination-to-source byte volume (data exfiltration or C2 amplification)',
  IN_PKTS: 'Inbound packet count indicating volumetric flood or scan burst intensity',
  OUT_PKTS: 'Outbound response packet count reflecting service reply or reverse shell activity',
  L4_DST_PORT: 'Target destination service port distinguishing port probes from application abuse',
  PROTOCOL: 'Layer-4 transport protocol identifier (TCP=6, UDP=17, ICMP=1)',
  L7_PROTO: 'Application-layer protocol signature (HTTP, DNS, SSH, MQTT, TLS)',
  TCP_FLAGS: 'Cumulative TCP control flags (SYN/ACK/RST/FIN handshake anomalies)',
  CLIENT_TCP_FLAGS: 'Client-initiated TCP flags (SYN flood or stealth FIN/NULL probe)',
  SERVER_TCP_FLAGS: 'Server response TCP flags (RST/ACK rejection during scanning)',
  FLOW_DURATION_MILLISECONDS: 'Total flow duration (micro-bursts in scans vs. persistent floods/C2)',
  MIN_TTL: 'Minimum IP Time-To-Live (hop-count spoofing or OS stack mismatch)',
  MAX_TTL: 'Maximum IP Time-To-Live across flow packets',
  LONGEST_FLOW_PKT: 'Maximum packet size in flow (exploit payload or jumbo exfil frame)',
  SHORTEST_FLOW_PKT: 'Minimum packet size (empty header probes in reconnaissance)',
  SRC_TO_DST_SECOND_BYTES: 'Source-to-destination byte rate per second',
  DST_TO_SRC_SECOND_BYTES: 'Destination-to-source byte rate per second',
  SRC_TO_DST_AVG_THROUGHPUT: 'Mean inbound throughput bit-rate',
  DST_TO_SRC_AVG_THROUGHPUT: 'Mean outbound throughput bit-rate',
  NUM_PKTS_UP_TO_128_BYTES: 'Count of tiny packets <=128B (SYN floods, port scans, C2 beacons)',
  NUM_PKTS_128_TO_256_BYTES: 'Count of small packets 128-256B (IoT firmware staging or credential probes)',
  NUM_PKTS_1024_TO_1514_BYTES: 'Count of MTU-sized frames (bulk data theft or encrypted exfiltration)',
  TCP_WIN_MAX_IN: 'Maximum inbound TCP receive window size (stack fingerprinting)',
  TCP_WIN_MAX_OUT: 'Maximum outbound TCP receive window size',
  DNS_QUERY_TYPE: 'DNS record query type (ANY/TXT amplification or DNS tunneling)',
  flow_duration: 'Elapsed flow duration in seconds across packet stream',
  Header_Length: 'Cumulative transport header byte length',
  Rate: 'Overall packet transmission rate per second',
  Srate: 'Source-to-destination packet transmission rate',
  IAT: 'Inter-arrival time between consecutive packets (botnet flood cadence)',
  syn_count: 'Count of TCP SYN flags in flow window',
  rst_count: 'Count of TCP RST connection resets',
  'Tot sum': 'Total summed packet lengths in capture window',
  AVG: 'Average packet size across flow window',
  MI_dir_L5_weight: 'Kitsune 5s source MAC-IP stream packet weight (botnet burst detector)',
  MI_dir_L5_mean: 'Kitsune 5s source MAC-IP packet length mean',
  MI_dir_L5_variance: 'Kitsune 5s source MAC-IP packet length variance',
  HH_L5_weight: 'Kitsune 5s host-to-host conversation packet weight',
  HH_jit_L5_mean: 'Kitsune 5s inter-packet jitter mean',
  HpHp_L5_magnitude: 'Kitsune 5s socket-to-socket bidirectional traffic magnitude',
};

function buildNetflowBaselines(): DatasetProfile['feature_baselines'] {
  const base: DatasetProfile['feature_baselines'] = {};
  const specs: Record<string, [number, number, number, number, string]> = {
    L4_DST_PORT: [443, 1800, 0, 65535, 'port'],
    PROTOCOL: [6, 3.2, 1, 17, 'proto'],
    L7_PROTO: [91, 45, 0, 244, 'id'],
    IN_BYTES: [1480, 950, 40, 250000, 'bytes'],
    IN_PKTS: [12, 8, 1, 8000, 'pkts'],
    OUT_BYTES: [2240, 1450, 0, 450000, 'bytes'],
    OUT_PKTS: [14, 9, 0, 6000, 'pkts'],
    TCP_FLAGS: [27, 8, 0, 255, 'mask'],
    CLIENT_TCP_FLAGS: [26, 7, 0, 255, 'mask'],
    SERVER_TCP_FLAGS: [24, 7, 0, 255, 'mask'],
    FLOW_DURATION_MILLISECONDS: [1850, 1200, 1, 120000, 'ms'],
    DURATION_IN: [920, 650, 0, 60000, 'ms'],
    DURATION_OUT: [880, 620, 0, 60000, 'ms'],
    MIN_TTL: [63, 8, 1, 255, 'hops'],
    MAX_TTL: [64, 8, 1, 255, 'hops'],
    LONGEST_FLOW_PKT: [640, 320, 40, 1514, 'bytes'],
    SHORTEST_FLOW_PKT: [54, 18, 28, 1500, 'bytes'],
    MIN_IP_PKT_LEN: [52, 16, 28, 1500, 'bytes'],
    MAX_IP_PKT_LEN: [640, 310, 40, 1514, 'bytes'],
    SRC_TO_DST_SECOND_BYTES: [1650, 1100, 0, 500000, 'B/s'],
    DST_TO_SRC_SECOND_BYTES: [2400, 1600, 0, 500000, 'B/s'],
    RETRANSMITTED_IN_BYTES: [0, 65, 0, 50000, 'bytes'],
    RETRANSMITTED_IN_PKTS: [0, 1.5, 0, 500, 'pkts'],
    RETRANSMITTED_OUT_BYTES: [0, 65, 0, 50000, 'bytes'],
    RETRANSMITTED_OUT_PKTS: [0, 1.5, 0, 500, 'pkts'],
    SRC_TO_DST_AVG_THROUGHPUT: [14500, 9000, 0, 5000000, 'bps'],
    DST_TO_SRC_AVG_THROUGHPUT: [19200, 12000, 0, 5000000, 'bps'],
    NUM_PKTS_UP_TO_128_BYTES: [7, 5, 0, 4000, 'pkts'],
    NUM_PKTS_128_TO_256_BYTES: [3, 3, 0, 1500, 'pkts'],
    NUM_PKTS_256_TO_512_BYTES: [2, 2, 0, 1000, 'pkts'],
    NUM_PKTS_512_TO_1024_BYTES: [2, 2, 0, 1000, 'pkts'],
    NUM_PKTS_1024_TO_1514_BYTES: [4, 3, 0, 2500, 'pkts'],
    TCP_WIN_MAX_IN: [29200, 12000, 0, 65535, 'bytes'],
    TCP_WIN_MAX_OUT: [28960, 12000, 0, 65535, 'bytes'],
    ICMP_TYPE: [0, 1, 0, 255, 'code'],
    ICMP_IPV4_TYPE: [0, 1, 0, 255, 'code'],
    DNS_QUERY_ID: [0, 400, 0, 65535, 'id'],
    DNS_QUERY_TYPE: [1, 2, 0, 255, 'type'],
    DNS_TTL_ANSWER: [60, 45, 0, 86400, 's'],
    FTP_COMMAND_RET_CODE: [0, 10, 0, 550, 'code'],
  };
  for (const name of NETFLOW_40_FEATURES) {
    const [mean, std, min, max, unit] = specs[name] ?? [10, 5, 0, 1000, 'val'];
    base[name] = {
      mean,
      std,
      min,
      max,
      unit,
      desc: FEATURE_SEMANTICS[name] ?? `Canonical telemetry feature ${name}`,
    };
  }
  return base;
}

function buildCicIotBaselines(): DatasetProfile['feature_baselines'] {
  const base: DatasetProfile['feature_baselines'] = {};
  const specs: Record<string, [number, number, number, number, string]> = {
    flow_duration: [4.2, 3.1, 0, 120, 's'],
    Header_Length: [180, 95, 20, 45000, 'bytes'],
    'Protocol Type': [6, 3.5, 1, 17, 'proto'],
    Duration: [64, 12, 1, 255, 'ttl'],
    Rate: [42, 35, 0, 85000, 'pkt/s'],
    Srate: [24, 20, 0, 60000, 'pkt/s'],
    Drate: [18, 15, 0, 40000, 'pkt/s'],
    syn_count: [1, 1.2, 0, 800, 'cnt'],
    rst_count: [0, 0.8, 0, 400, 'cnt'],
    ack_count: [6, 4, 0, 1200, 'cnt'],
    'Tot sum': [3200, 1800, 60, 500000, 'bytes'],
    AVG: [260, 140, 40, 1514, 'bytes'],
    IAT: [0.085, 0.045, 0.0001, 10, 's'],
    Number: [9.5, 4, 1, 500, 'cnt'],
    Weight: [141, 45, 1, 1000, 'w'],
  };
  for (const name of CICIOT_46_FEATURES) {
    const [mean, std, min, max, unit] = specs[name] ?? [0.5, 0.4, 0, 100, 'val'];
    base[name] = {
      mean,
      std,
      min,
      max,
      unit,
      desc: FEATURE_SEMANTICS[name] ?? `CIC-IoT-2023 behavioral metric ${name}`,
    };
  }
  return base;
}

function buildNBaiotBaselines(): DatasetProfile['feature_baselines'] {
  const base: DatasetProfile['feature_baselines'] = {};
  for (const name of NBAIOT_115_FEATURES) {
    let mean = 2.4;
    let std = 1.6;
    let max = 10000;
    let unit = 'stat';
    if (name.includes('weight')) {
      mean = 18;
      std = 12;
      max = 25000;
      unit = 'w';
    } else if (name.includes('mean')) {
      mean = 92;
      std = 38;
      max = 1514;
      unit = 'bytes';
    } else if (name.includes('variance') || name.includes('std')) {
      mean = 140;
      std = 95;
      max = 250000;
      unit = 'var';
    } else if (name.includes('pcc')) {
      mean = 0.05;
      std = 0.22;
      max = 1;
      unit = 'corr';
    }
    base[name] = {
      mean,
      std,
      min: name.includes('pcc') ? -1 : 0,
      max,
      unit,
      desc: FEATURE_SEMANTICS[name] ?? `Kitsune temporal window statistic ${name}`,
    };
  }
  return base;
}

const NF_BASELINES = buildNetflowBaselines();
const CICIOT_BASELINES = buildCicIotBaselines();
const NBAIOT_BASELINES = buildNBaiotBaselines();

export const DATASET_PROFILES: Record<string, DatasetProfile> = {
  'NF-BoT-IoT-v2': {
    id: 'NF-BoT-IoT-v2',
    display_name: 'NF-BoT-IoT-v2 (IoT Botnet Telemetry)',
    family: 'NetFlow-v2',
    feature_count: 40,
    raw_feature_names: NETFLOW_40_FEATURES,
    known_classes: ['Benign', 'DDoS', 'DoS', 'Reconnaissance'],
    zero_day_classes: ['Theft'],
    tau_amber: 1.65,
    tau_red: 2.45,
    benchmark: {
      total_classes: 5,
      unique_rows: 791753,
      closed_macro_f1: 98.16,
      closed_acc: 97.96,
      closed_fpr: 0.07,
      open_benign_fpr: 0.78,
      ood_auroc_known: 92.92,
      oscr: 91.1,
      single_flow_ms: 3.951,
      throughput_fps: 188727,
      ece_pct: 0.23,
      evasion_auroc: 99.95,
    },
    feature_baselines: NF_BASELINES,
  },
  'NF-UNSW-NB15-v2': {
    id: 'NF-UNSW-NB15-v2',
    display_name: 'NF-UNSW-NB15-v2 (Enterprise Hybrid)',
    family: 'NetFlow-v2',
    feature_count: 40,
    raw_feature_names: NETFLOW_40_FEATURES,
    known_classes: ['Benign', 'Analysis', 'Backdoor', 'DoS', 'Exploits', 'Fuzzers', 'Generic', 'Reconnaissance'],
    zero_day_classes: ['Worms', 'Shellcode'],
    tau_amber: 1.72,
    tau_red: 2.55,
    benchmark: {
      total_classes: 10,
      unique_rows: 421820,
      closed_macro_f1: 82.75,
      closed_acc: 98.25,
      closed_fpr: 0.2,
      open_benign_fpr: 0.95,
      ood_auroc_known: 92.14,
      oscr: 90.9,
      single_flow_ms: 3.888,
      throughput_fps: 186592,
      ece_pct: 0.18,
      evasion_auroc: 99.43,
    },
    feature_baselines: NF_BASELINES,
  },
  'NF-ToN-IoT-v2': {
    id: 'NF-ToN-IoT-v2',
    display_name: 'NF-ToN-IoT-v2 (Industrial IIoT)',
    family: 'NetFlow-v2',
    feature_count: 40,
    raw_feature_names: NETFLOW_40_FEATURES,
    known_classes: ['Benign', 'backdoor', 'ddos', 'dos', 'injection', 'password', 'scanning', 'xss'],
    zero_day_classes: ['ransomware', 'mitm'],
    tau_amber: 1.68,
    tau_red: 2.5,
    benchmark: {
      total_classes: 10,
      unique_rows: 1930229,
      closed_macro_f1: 90.05,
      closed_acc: 89.68,
      closed_fpr: 2.66,
      open_benign_fpr: 3.57,
      ood_auroc_known: 74.52,
      oscr: 67.68,
      single_flow_ms: 3.66,
      throughput_fps: 187620,
      ece_pct: 0.51,
      evasion_auroc: 99.86,
    },
    feature_baselines: NF_BASELINES,
  },
  'NF-CSE-CIC-IDS2018-v2': {
    id: 'NF-CSE-CIC-IDS2018-v2',
    display_name: 'NF-CSE-CIC-IDS2018-v2 (Cloud Enterprise)',
    family: 'NetFlow-v2',
    feature_count: 40,
    raw_feature_names: NETFLOW_40_FEATURES,
    known_classes: [
      'Benign', 'Bot', 'Brute Force -Web', 'DDOS attack-HOIC', 'DDOS attack-LOIC-UDP',
      'DDoS attacks-LOIC-HTTP', 'DoS attacks-GoldenEye', 'DoS attacks-Hulk',
      'DoS attacks-SlowHTTPTest', 'DoS attacks-Slowloris', 'FTP-BruteForce', 'SSH-Bruteforce',
    ],
    zero_day_classes: ['Infilteration', 'Brute Force -XSS', 'SQL Injection'],
    tau_amber: 1.75,
    tau_red: 2.6,
    benchmark: {
      total_classes: 15,
      unique_rows: 880922,
      closed_macro_f1: 94.05,
      closed_acc: 99.79,
      closed_fpr: 0.02,
      open_benign_fpr: 0.89,
      ood_auroc_known: 58.4,
      oscr: 58.31,
      single_flow_ms: 3.513,
      throughput_fps: 187965,
      ece_pct: 0.01,
      evasion_auroc: 98.33,
    },
    feature_baselines: NF_BASELINES,
  },
  'N-BaIoT': {
    id: 'N-BaIoT',
    display_name: 'N-BaIoT (115-Feat IoT Botnet Kitsune)',
    family: 'N-BaIoT',
    feature_count: 115,
    raw_feature_names: NBAIOT_115_FEATURES,
    known_classes: [
      'Benign', 'gafgyt_combo', 'gafgyt_junk', 'gafgyt_scan', 'gafgyt_udp',
      'mirai_ack', 'mirai_scan', 'mirai_syn', 'mirai_udpplain',
    ],
    zero_day_classes: ['mirai_udp', 'gafgyt_tcp'],
    tau_amber: 1.6,
    tau_red: 2.35,
    benchmark: {
      total_classes: 11,
      unique_rows: 736593,
      closed_macro_f1: 99.98,
      closed_acc: 99.99,
      closed_fpr: 0.03,
      open_benign_fpr: 0.78,
      ood_auroc_known: 99.6,
      oscr: 99.6,
      single_flow_ms: 4.191,
      throughput_fps: 166930,
      ece_pct: 0.01,
      evasion_auroc: 99.83,
    },
    feature_baselines: NBAIOT_BASELINES,
  },
  'CIC-IoT-2023-34Class': {
    id: 'CIC-IoT-2023-34Class',
    display_name: 'CIC-IoT-2023 (34-Class Granular IoT)',
    family: 'CIC-IoT-2023',
    feature_count: 46,
    raw_feature_names: CICIOT_46_FEATURES,
    known_classes: [
      'Benign', 'BrowserHijacking', 'DDoS-ACK_Fragmentation', 'DDoS-HTTP_Flood', 'DDoS-ICMP_Flood',
      'DDoS-ICMP_Fragmentation', 'DDoS-PSHACK_Flood', 'DDoS-RSTFINFlood', 'DDoS-SYN_Flood',
      'DDoS-SlowLoris', 'DDoS-SynonymousIP_Flood', 'DDoS-TCP_Flood', 'DDoS-UDP_Flood',
      'DDoS-UDP_Fragmentation', 'DNS_Spoofing', 'DictionaryBruteForce', 'DoS-HTTP_Flood',
      'DoS-SYN_Flood', 'DoS-TCP_Flood', 'DoS-UDP_Flood', 'MITM-ArpSpoofing', 'Mirai-greip_flood',
      'Recon-HostDiscovery', 'Recon-OSScan', 'Recon-PingSweep', 'Recon-PortScan',
      'Uploading_Attack', 'VulnerabilityScan',
    ],
    zero_day_classes: [
      'Mirai-greeth_flood', 'Mirai-udpplain', 'SqlInjection', 'CommandInjection', 'XSS', 'Backdoor_Malware',
    ],
    tau_amber: 1.7,
    tau_red: 2.48,
    benchmark: {
      total_classes: 34,
      unique_rows: 1230774,
      closed_macro_f1: 88.49,
      closed_acc: 96.95,
      closed_fpr: 2.78,
      open_benign_fpr: 3.23,
      ood_auroc_known: 85.5,
      oscr: 83.63,
      single_flow_ms: 4.311,
      throughput_fps: 182941,
      ece_pct: 0.67,
      evasion_auroc: 99.67,
    },
    feature_baselines: CICIOT_BASELINES,
  },
};

export type FlowPresetKind =
  | 'BENIGN_NORMAL'
  | 'KNOWN_DDOS'
  | 'ZERO_DAY_THEFT'
  | 'AMBIGUOUS_BOUNDARY'
  | 'GRAY_ZONE_STEALTH';

export function buildPresetFeatures(
  profileId: string,
  preset: FlowPresetKind
): { features: Record<string, number>; socket: { src_ip: string; dst_ip: string; src_port: number; dst_port: number; protocol: number } } {
  const profile = DATASET_PROFILES[profileId] ?? DATASET_PROFILES['NF-BoT-IoT-v2'];
  const features: Record<string, number> = {};
  for (const fname of profile.raw_feature_names) {
    features[fname] = profile.feature_baselines[fname]?.mean ?? 0;
  }

  if (profile.family === 'NetFlow-v2') {
    if (preset === 'BENIGN_NORMAL') {
      return {
        features: {
          ...features,
          L4_DST_PORT: 443,
          PROTOCOL: 6,
          L7_PROTO: 91,
          IN_BYTES: 1420,
          IN_PKTS: 11,
          OUT_BYTES: 2380,
          OUT_PKTS: 14,
          TCP_FLAGS: 27,
          FLOW_DURATION_MILLISECONDS: 1620,
          NUM_PKTS_UP_TO_128_BYTES: 6,
          NUM_PKTS_128_TO_256_BYTES: 3,
          NUM_PKTS_1024_TO_1514_BYTES: 4,
          MIN_TTL: 64,
          MAX_TTL: 64,
        },
        socket: { src_ip: '10.20.14.22', dst_ip: '192.168.10.5', src_port: 51422, dst_port: 443, protocol: 6 },
      };
    }
    if (preset === 'KNOWN_DDOS') {
      return {
        features: {
          ...features,
          L4_DST_PORT: 80,
          PROTOCOL: 6,
          L7_PROTO: 7,
          IN_BYTES: 148500,
          IN_PKTS: 2450,
          OUT_BYTES: 0,
          OUT_PKTS: 0,
          TCP_FLAGS: 2,
          CLIENT_TCP_FLAGS: 2,
          SERVER_TCP_FLAGS: 0,
          FLOW_DURATION_MILLISECONDS: 410,
          SRC_TO_DST_SECOND_BYTES: 362195,
          SRC_TO_DST_AVG_THROUGHPUT: 2897560,
          NUM_PKTS_UP_TO_128_BYTES: 2420,
          MIN_TTL: 48,
          MAX_TTL: 48,
          TCP_WIN_MAX_IN: 512,
        },
        socket: { src_ip: '185.220.101.44', dst_ip: '10.20.30.10', src_port: 49152, dst_port: 80, protocol: 6 },
      };
    }
    if (preset === 'ZERO_DAY_THEFT') {
      return {
        features: {
          ...features,
          L4_DST_PORT: 1883,
          PROTOCOL: 6,
          L7_PROTO: 222,
          IN_BYTES: 960,
          IN_PKTS: 14,
          OUT_BYTES: 384200,
          OUT_PKTS: 296,
          TCP_FLAGS: 24,
          FLOW_DURATION_MILLISECONDS: 48900,
          DST_TO_SRC_SECOND_BYTES: 294500,
          DST_TO_SRC_AVG_THROUGHPUT: 3420000,
          LONGEST_FLOW_PKT: 1514,
          NUM_PKTS_1024_TO_1514_BYTES: 282,
          NUM_PKTS_128_TO_256_BYTES: 48,
          RETRANSMITTED_OUT_BYTES: 18400,
          RETRANSMITTED_OUT_PKTS: 28,
          MIN_TTL: 118,
          MAX_TTL: 127,
          TCP_WIN_MAX_OUT: 65535,
        },
        socket: { src_ip: '10.20.30.99', dst_ip: '91.214.124.88', src_port: 58312, dst_port: 1883, protocol: 6 },
      };
    }
    if (preset === 'AMBIGUOUS_BOUNDARY') {
      return {
        features: {
          ...features,
          L4_DST_PORT: 8080,
          PROTOCOL: 6,
          IN_BYTES: 2950,
          IN_PKTS: 48,
          OUT_BYTES: 460,
          OUT_PKTS: 9,
          TCP_FLAGS: 22,
          SERVER_TCP_FLAGS: 20,
          FLOW_DURATION_MILLISECONDS: 310,
          NUM_PKTS_UP_TO_128_BYTES: 44,
          NUM_PKTS_128_TO_256_BYTES: 11,
          SHORTEST_FLOW_PKT: 40,
          MIN_TTL: 58,
        },
        socket: { src_ip: '10.20.14.87', dst_ip: '10.20.30.15', src_port: 44218, dst_port: 8080, protocol: 6 },
      };
    }
    // GRAY_ZONE_STEALTH
    return {
      features: {
        ...features,
        L4_DST_PORT: 8443,
        PROTOCOL: 6,
        IN_BYTES: 5400,
        IN_PKTS: 42,
        OUT_BYTES: 34800,
        OUT_PKTS: 38,
        TCP_FLAGS: 25,
        FLOW_DURATION_MILLISECONDS: 19400,
        NUM_PKTS_128_TO_256_BYTES: 26,
        NUM_PKTS_UP_TO_128_BYTES: 31,
        DST_TO_SRC_SECOND_BYTES: 18200,
        RETRANSMITTED_IN_PKTS: 5,
        MIN_TTL: 52,
      },
      socket: { src_ip: '172.16.40.73', dst_ip: '10.20.30.22', src_port: 53904, dst_port: 8443, protocol: 6 },
    };
  }

  if (profile.family === 'CIC-IoT-2023') {
    if (preset === 'KNOWN_DDOS') {
      return {
        features: { ...features, Rate: 42000, Srate: 41800, syn_count: 520, Header_Length: 24500, IAT: 0.0002, flow_duration: 0.4, 'Tot sum': 195000 },
        socket: { src_ip: '198.51.100.77', dst_ip: '10.20.30.40', src_port: 39102, dst_port: 80, protocol: 6 },
      };
    }
    if (preset === 'ZERO_DAY_THEFT') {
      return {
        features: { ...features, flow_duration: 64.5, Rate: 620, Header_Length: 31200, 'Tot sum': 420000, AVG: 1380, Std: 410, IAT: 0.003, rst_count: 145, urg_count: 28 },
        socket: { src_ip: '10.20.30.104', dst_ip: '45.155.205.33', src_port: 60120, dst_port: 8883, protocol: 6 },
      };
    }
    if (preset === 'AMBIGUOUS_BOUNDARY') {
      return {
        features: { ...features, Rate: 280, Srate: 190, syn_count: 18, rst_count: 11, flow_duration: 1.8, AVG: 98, IAT: 0.015 },
        socket: { src_ip: '10.20.14.91', dst_ip: '10.20.30.18', src_port: 47210, dst_port: 8080, protocol: 6 },
      };
    }
    if (preset === 'GRAY_ZONE_STEALTH') {
      return {
        features: { ...features, flow_duration: 24.0, Rate: 185, Header_Length: 4200, 'Tot sum': 48500, AVG: 740, IAT: 0.022, rst_count: 24 },
        socket: { src_ip: '172.16.40.81', dst_ip: '10.20.30.12', src_port: 51109, dst_port: 4444, protocol: 6 },
      };
    }
    return {
      features,
      socket: { src_ip: '10.20.14.15', dst_ip: '192.168.10.20', src_port: 50120, dst_port: 443, protocol: 6 },
    };
  }

  // N-BaIoT (115 features)
  if (preset === 'KNOWN_DDOS') {
    return {
      features: { ...features, MI_dir_L5_weight: 8400, H_L5_weight: 8350, HH_L5_weight: 7900, MI_dir_L5_mean: 64, HH_jit_L5_mean: 0.001, HpHp_L5_magnitude: 9200 },
      socket: { src_ip: '10.20.88.14', dst_ip: '198.51.100.12', src_port: 45123, dst_port: 53, protocol: 17 },
    };
  }
  if (preset === 'ZERO_DAY_THEFT') {
    return {
      features: { ...features, MI_dir_L5_weight: 1920, MI_dir_L5_mean: 1410, MI_dir_L5_variance: 142000, HH_L5_weight: 1850, HH_L5_radius: 1950, HpHp_L5_magnitude: 2450, HH_jit_L5_variance: 9400 },
      socket: { src_ip: '10.20.88.42', dst_ip: '91.214.124.88', src_port: 52910, dst_port: 1883, protocol: 17 },
    };
  }
  if (preset === 'AMBIGUOUS_BOUNDARY') {
    return {
      features: { ...features, MI_dir_L5_weight: 145, H_L5_weight: 138, HH_L5_weight: 120, MI_dir_L5_variance: 820 },
      socket: { src_ip: '10.20.88.19', dst_ip: '10.20.30.15', src_port: 41200, dst_port: 8080, protocol: 6 },
    };
  }
  if (preset === 'GRAY_ZONE_STEALTH') {
    return {
      features: { ...features, MI_dir_L5_weight: 290, MI_dir_L5_mean: 420, MI_dir_L5_variance: 6800, HH_jit_L5_mean: 0.42, HpHp_L5_magnitude: 680 },
      socket: { src_ip: '10.20.88.33', dst_ip: '10.20.30.9', src_port: 56210, dst_port: 2323, protocol: 6 },
    };
  }
  return {
    features,
    socket: { src_ip: '10.20.88.5', dst_ip: '192.168.10.2', src_port: 49901, dst_port: 443, protocol: 6 },
  };
}
