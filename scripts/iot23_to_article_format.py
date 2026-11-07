"""
Adapta o conn.log.labeled do IoT-23 para o formato do artigo.
- Timestamp: coluna 'ts'
- Packet Length: orig_ip_bytes / orig_pkts (tamanho medio de pacote outbound)
- Label: 'Malicious' ou 'Benign'
"""
import pandas as pd
import numpy as np
import sys

def adapt_conn_log(input_path, output_csv, label_filter=None):
    df = pd.read_csv(
        input_path,
        sep='\t',
        comment='#',
        header=None,
        names=[
            'ts','uid','id_orig_h','id_orig_p','id_resp_h','id_resp_p',
            'proto','service','duration','orig_bytes','resp_bytes',
            'conn_state','local_orig','local_resp','missed_bytes',
            'history','orig_pkts','orig_ip_bytes','resp_pkts',
            'resp_ip_bytes','tunnel_parents','label','detailed_label'
        ],
        low_memory=False
    )

    df = df.replace('-', np.nan)

    for col in ['ts','orig_ip_bytes','orig_pkts','resp_ip_bytes','resp_pkts','duration']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    if label_filter:
        df = df[df['label'].isin(label_filter)]

    df = df.dropna(subset=['ts', 'orig_ip_bytes', 'orig_pkts'])
    df = df[df['orig_pkts'] > 0]

    df['packet_length'] = df['orig_ip_bytes'] / df['orig_pkts']

    out = pd.DataFrame({
        'Timestamp': df['ts'].values,
        'Packet Length': df['packet_length'].values,
        'Label': df['label'].values,
        'Src IP': df['id_orig_h'].values,
    }).sort_values('Timestamp').reset_index(drop=True)

    out.to_csv(output_csv, index=False)
    print(f"OK: {len(out)} fluxos -> {output_csv}")
    print(f"Classes: {out['Label'].value_counts().to_dict()}")
    print(f"Timestamp: {out['Timestamp'].min():.0f} a {out['Timestamp'].max():.0f}")
    print(f"Packet Length: {out['Packet Length'].describe()}")

if __name__ == '__main__':
    adapt_conn_log(sys.argv[1], sys.argv[2])
