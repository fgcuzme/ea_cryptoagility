#!/usr/bin/env python3
# ============================================================
# SCRIPT: Consolidado de Estadísticas Criptográficas del Tangle
# Para procesar 30 runs y generar estadísticas para el paper
# Excluye el sink (node_id = 0)
# ============================================================

import pandas as pd
import numpy as np
import glob
import os
from datetime import datetime

# ============================================================
# CONFIGURACIÓN - AJUSTAR SEGÚN TU ESTRUCTURA
# ============================================================

# Directorio base donde están los archivos - results_W5_Sh0.5_1000m_per0.10
# BASE_DIR = r"C:/compilables_embed/results_W5_Sh0.5_1000m_per0.50/nodes_200/"
BASE_DIR = r"G:/Mi unidad/PhD_UMalaga\AÑO 7 2026/Utangle_code/results/"

# Patrón de archivos de eventos del tangle
EVENTS_PATTERN = "**/tangle_events_light.csv"

# Excluir sink (node_id = 0)
EXCLUDE_SINK = True
SINK_NODE_ID = 0

# ============================================================
# FUNCIONES DE CARGA
# ============================================================

def load_all_tangle_events(base_dir, pattern):
    """Carga todos los archivos de eventos tangle"""
    files = glob.glob(os.path.join(base_dir, pattern), recursive=True)
    print(f"\nEncontrados {len(files)} archivos de eventos tangle")

    dfs = []
    for f in sorted(files):
        try:
            df = pd.read_csv(f)
            if 'run_id' not in df.columns:
                run_part = os.path.basename(f).split('run')[-1].split('.')[0]
                df['run_id'] = f"run{run_part}"
            dfs.append(df)
            print(f"  OK {os.path.basename(f)}: {len(df)} registros")
        except Exception as e:
            print(f"  ERROR en {f}: {e}")

    if dfs:
        combined = pd.concat(dfs, ignore_index=True)
        print(f"\nTotal combinado: {len(combined)} registros")
        return combined
    return pd.DataFrame()

# ============================================================
# FUNCIONES DE ANÁLISIS
# ============================================================

def compute_stats(series):
    """Calcula estadísticas descriptivas para una serie"""
    return {
        'n': int(len(series)),
        'mean_ms': float(series.mean()),
        'std_ms': float(series.std()),
        'min_ms': float(series.min()),
        'p25_ms': float(series.quantile(0.25)),
        'p50_ms': float(series.median()),
        'p75_ms': float(series.quantile(0.75)),
        'p90_ms': float(series.quantile(0.90)),
        'p95_ms': float(series.quantile(0.95)),
        'p99_ms': float(series.quantile(0.99)),
        'max_ms': float(series.max())
    }

def analyze_crypto_stats(df, exclude_sink=True, sink_id=0):
    """Analiza estadísticas criptográficas excluyendo el sink"""

    if exclude_sink and 'node_id' in df.columns:
        original_len = len(df)
        df = df[df['node_id'] != sink_id].copy()
        print(f"\nExcluido sink (node_id={sink_id}): {original_len} -> {len(df)} registros")

    results = {}

    # 1. ED25519.sign()
    sign_data = df[df['op'] == 'create_tx']['t_sign'].dropna()
    if len(sign_data) > 0:
        results['ED25519.sign()'] = compute_stats(sign_data)

    # 2. ED25519.verify()
    verify_data = df[df['op'] == 'verify_tx']['t_verify'].dropna()
    if len(verify_data) > 0:
        results['ED25519.verify()'] = compute_stats(verify_data)

    # 3. Ascon-Hash
    hash_data = df[df['op'] == 'create_tx']['t_hash'].dropna()
    if len(hash_data) > 0:
        results['Ascon-Hash'] = compute_stats(hash_data)

    # 4. Canonicalization
    canon_data = df[df['op'] == 'create_tx']['t_canon'].dropna()
    if len(canon_data) > 0:
        results['Canonicalization'] = compute_stats(canon_data)

    # 5. Tips Selection
    tips_data = df[df['op'].isin(['create_tx', 'tips_select'])]['t_tips_sel'].dropna()
    if len(tips_data) > 0:
        results['Tips Selection'] = compute_stats(tips_data)

    # 6. RX Checks
    rx_checks = df[df['op'] == 'rx_checks']

    nonce_data = rx_checks['t_nonce_chk'].dropna()
    if len(nonce_data) > 0:
        results['Nonce Check'] = compute_stats(nonce_data)

    ts_data = rx_checks['t_ts_chk'].dropna()
    if len(ts_data) > 0:
        results['Timestamp Check'] = compute_stats(ts_data)

    replay_data = rx_checks['t_replay_chk'].dropna()
    if len(replay_data) > 0:
        results['Replay Check'] = compute_stats(replay_data)

    # 7. Total TX Creation
    total_create = df[df['op'] == 'create_tx']['t_total'].dropna()
    if len(total_create) > 0:
        results['Total TX Creation'] = compute_stats(total_create)

    # 8. Total TX Verify
    total_verify = df[df['op'] == 'verify_tx']['t_total'].dropna()
    if len(total_verify) > 0:
        results['Total TX Verify'] = compute_stats(total_verify)

    return results

def analyze_dag_structure(df, exclude_sink=True, sink_id=0):
    """Analiza estructura del DAG"""

    if exclude_sink and 'node_id' in df.columns:
        df = df[df['node_id'] != sink_id].copy()

    results = {}

    # Tips
    tips_store = df[df['op'] == 'tips_store']
    if 'tips_after' in tips_store.columns:
        tips_after = tips_store['tips_after'].dropna()
        if len(tips_after) > 0:
            results['tips'] = {
                'n': len(tips_after),
                'mean': tips_after.mean(),
                'std': tips_after.std(),
                'min': tips_after.min(),
                'max': tips_after.max()
            }

    # TX Size
    if 'tx_bytes' in df.columns:
        tx_bytes = df['tx_bytes'].dropna()
        if len(tx_bytes) > 0:
            results['tx_size'] = {
                'n': len(tx_bytes),
                'mean_bytes': tx_bytes.mean(),
                'std_bytes': tx_bytes.std(),
                'min_bytes': tx_bytes.min(),
                'max_bytes': tx_bytes.max()
            }

    # Success rates
    results['success_rates'] = {}
    for col in ['sig_ok', 'nonce_ok', 'ts_ok', 'replay_ok']:
        if col in df.columns:
            data = df[col].dropna()
            if len(data) > 0:
                success = (data == True).sum() + (data == 'True').sum()
                results['success_rates'][col] = {
                    'total': len(data),
                    'success': int(success),
                    'rate': float(success / len(data) * 100)
                }

    return results

def analyze_by_run(df, exclude_sink=True, sink_id=0):
    """Analiza estadísticas por run"""

    if exclude_sink and 'node_id' in df.columns:
        df = df[df['node_id'] != sink_id].copy()

    if 'run_id' not in df.columns:
        return pd.DataFrame()

    runs = df['run_id'].unique()

    run_stats = []
    for run in sorted(runs):
        run_df = df[df['run_id'] == run]

        sign_times = run_df[run_df['op'] == 'create_tx']['t_sign'].dropna()
        verify_times = run_df[run_df['op'] == 'verify_tx']['t_verify'].dropna()
        hash_times = run_df[run_df['op'] == 'create_tx']['t_hash'].dropna()

        run_stats.append({
            'run_id': run,
            'n_events': len(run_df),
            'sign_mean_ms': sign_times.mean() if len(sign_times) > 0 else None,
            'verify_mean_ms': verify_times.mean() if len(verify_times) > 0 else None,
            'hash_mean_ms': hash_times.mean() if len(hash_times) > 0 else None
        })

    return pd.DataFrame(run_stats)

# ============================================================
# EJECUCIÓN PRINCIPAL
# ============================================================

if __name__ == "__main__":

    print("="*80)
    print("CONSOLIDADO DE ESTADÍSTICAS CRIPTOGRÁFICAS DEL TANGLE")
    print("="*80)

    # 1. Cargar datos
    all_events = load_all_tangle_events(BASE_DIR, EVENTS_PATTERN)

    if len(all_events) == 0:
        print("\nNo se encontraron archivos. Verifica BASE_DIR y EVENTS_PATTERN")
        exit(1)

    # 2. Análisis criptográfico
    print("\n" + "="*80)
    print("ESTADÍSTICAS CRIPTOGRÁFICAS (Excluyendo Sink)")
    print("="*80)

    crypto_stats = analyze_crypto_stats(all_events)
    crypto_df = pd.DataFrame(crypto_stats).T
    print("\n" + crypto_df.round(4).to_string())

    # 3. Estructura DAG
    print("\n" + "="*80)
    print("ESTRUCTURA DEL DAG")
    print("="*80)

    dag_stats = analyze_dag_structure(all_events)
    for section, data in dag_stats.items():
        print(f"\n{section}:")
        if isinstance(data, dict):
            for k, v in data.items():
                print(f"  {k}: {v}")

    # 4. Exportar
    crypto_df.to_csv(os.path.join(BASE_DIR,f"crypto_stats_consolidated.csv"))
    print("\nGuardado: crypto_stats_consolidated.csv")

    print("\n¡ANÁLISIS COMPLETO!")
