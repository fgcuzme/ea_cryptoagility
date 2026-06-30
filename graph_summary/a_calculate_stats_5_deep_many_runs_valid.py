# 2. Código para Procesamiento

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import glob
import os
from pathlib import Path
from scipy import stats

class CargadorDatosExperimental:
    def __init__(self, base_path):
        self.base_path = Path(base_path)
        self.df = None
        
    def cargar_todas_ejecuciones(self, runs_range=None):
        """Carga todas las ejecuciones disponibles"""
        if runs_range is None:
            # Buscar automáticamente todas las ejecuciones
            runs_dirs = list(self.base_path.glob("run_*"))
            runs_range = sorted([int(str(dir.name).split('_')[1]) for dir in runs_dirs 
                               if str(dir.name).split('_')[1].isdigit()])
        
        df_list = []
        runs_cargadas = 0
        
        for run_num in runs_range:
            archivo = self.base_path / f"run_{run_num}" / "transmissions.csv"
            
            if archivo.exists():
                try:
                    temp_df = pd.read_csv(archivo)
                    
                    # Enriquecer datos con metadatos
                    temp_df['run_id'] = f"run_{run_num:02d}"
                    temp_df['run_number'] = run_num
                    temp_df['config_nodos'] = str(self.base_path).split('_')[-1]  # Extrae nodes_XX
                    
                    df_list.append(temp_df)
                    runs_cargadas += 1
                    print(f"✅ Run {run_num:02d}: {len(temp_df):>4} transmisiones")
                    
                except Exception as e:
                    print(f"❌ Error en run_{run_num:02d}: {e}")
            else:
                print(f"⚠️  No encontrado: run_{run_num:02d}")
        
        if df_list:
            self.df = pd.concat(df_list, ignore_index=True)
            print(f"\n🎯 CARGA COMPLETADA: {runs_cargadas} ejecuciones, {len(self.df):,} registros totales")
            return self.df
        else:
            print("❌ No se pudieron cargar datos")
            return None
    
    def generar_reporte_carga(self):
        """Genera un reporte detallado de los datos cargados"""
        if self.df is None:
            print("No hay datos cargados")
            return
        
        print("\n" + "="*60)
        print("📊 REPORTE DE DATOS CARGADOS")
        print("="*60)
        
        # Estadísticas generales
        print(f"Total de registros: {len(self.df):,}")
        print(f"Ejecuciones cargadas: {self.df['run_id'].nunique()}")
        print(f"Rango de runs: {self.df['run_number'].min()} - {self.df['run_number'].max()}")
        
        # Estadísticas por run
        stats_run = self.df.groupby('run_id').agg({
            'timestamp_iso': 'count',
            'latency_ms': ['mean', 'std'],
            'energy_j': ['sum', 'mean'],
            'success': 'mean',
            'distance_m': 'mean'
        }).round(3)
        
        # Renombrar columnas para mejor legibilidad
        stats_run.columns = ['n_transmisiones', 'latencia_mean', 'latencia_std', 
                           'energia_total', 'energia_mean', 'tasa_exito', 'distancia_mean']
        
        print("\n📈 Estadísticas por ejecución:")
        print(stats_run)
        
        # Resumen consolidado
        print("\n🎯 Resumen consolidado de todas las ejecuciones:")
        print(f"• Transmisiones totales: {len(self.df):,}")
        print(f"• Tasa de éxito promedio: {self.df['success'].mean()*100:.2f}%")
        print(f"• Latencia promedio: {self.df['latency_ms'].mean():.2f} ms")
        print(f"• Energía total consumida: {self.df['energy_j'].sum():.2f} J")
        print(f"• Distancia promedio: {self.df['distance_m'].mean():.2f} m")
        
        return stats_run

# USO DEL CÓDIGO
if __name__ == "__main__":
    # Configurar la ruta base - AJUSTA ESTA RUTA SEGÚN TU CASO
    # base_path = r"stats\results_new_embed_rapb\nodes_500"
    base_path = r"C:\compilables_embed\results_W5_Sh0.5_1000m\nodes_200"
    num_nodes = 200

    # Crear cargador y cargar datos
    cargador = CargadorDatosExperimental(base_path)
    df = cargador.cargar_todas_ejecuciones(runs_range=range(1, 31))  # Runs 1-30
    
    # Rutas de carga
    output_dir = "C:/compilables_embed/results_W5_Sh0.5_1000m"
    os.makedirs(output_dir, exist_ok=True)

    if df is not None:
        # Generar reporte
        statss = cargador.generar_reporte_carga()
        
        # Guardar datos consolidados
        df.to_csv(os.path.join(output_dir, f"datos_30_runs_consolidados_{num_nodes}.csv"), index=False)

        # df.to_csv(f"datos_30_runs_consolidados_{num_nodes}.csv", index=False)
        print("\n💾 Datos guardados en: 'datos_30_runs_consolidados.csv'")
        
        # Visualización rápida de distribución por run
        plt.figure(figsize=(12, 6))
        df['run_number'].value_counts().sort_index().plot(kind='bar')
        plt.title('Número de Transmisiones por Ejecución')
        plt.xlabel('Número de Ejecución')
        plt.ylabel('Transmisiones')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()


    # Análisis inicial de los datos cargados
    if df is not None:
        print("\n" + "="*50)
        print("RESUMEN DE DATOS CARGADOS")
        print("="*50)
        
        print(f"Total de registros: {len(df):,}")
        print(f"Ejecuciones cargadas: {df['run_id'].nunique()}")
        print(f"Rango de ejecuciones: {df['run_number'].min()} - {df['run_number'].max()}")
        
        # Verificar que tenemos las 30 ejecuciones esperadas
        runs_esperadas = 30
        runs_cargadas = df['run_id'].nunique()
        
        if runs_cargadas == runs_esperadas:
            print("✅ ¡Se cargaron todas las 30 ejecuciones!")
        else:
            print(f"⚠️  Se cargaron {runs_cargadas} de {runs_esperadas} ejecuciones")
        
        # Estadísticas básicas por ejecución
        print("\nEstadísticas por ejecución:")
        stats_por_run = df.groupby('run_id').agg({
            'timestamp_iso': 'count',
            'latency_ms': 'mean',
            'energy_j': 'sum',
            'success': 'mean'
        }).round(3)
        
        stats_por_run.columns = ['n_transmisiones', 'latencia_promedio', 'energia_total', 'tasa_exito']
        print(stats_por_run)
        
        # # Guardar datos consolidados para análisis futuro
        # output_file = f"datos_consolidados_30_runs_{num_nodes}.csv"
        # df.to_csv(output_file, index=False)
        # print(f"\n💾 Datos consolidados guardados en: {output_file}")
        
    else:
        print("❌ No se pudieron cargar los datos")

    # 3. Cálculo de Métricas por Run
    # Métricas por run
    run_metrics = df.groupby('run_id').agg({
        'latency_ms': ['mean', 'std', 'min', 'max'],
        'energy_j': ['sum', 'mean', 'std'],
        'success': 'mean',
        'distance_m': 'mean',
        'sender_id': 'nunique',  # número de nodos únicos que transmiten
        'timestamp_iso': 'count'  # número total de transmisiones
    }).round(4)

    # Renombrar columnas
    run_metrics.columns = [
        'latency_mean', 'latency_std', 'latency_min', 'latency_max',
        'energy_total', 'energy_mean', 'energy_std',
        'success_rate',
        'distance_mean',
        'unique_nodes',
        'total_transmissions'
    ]

    # Calcular Packet Delivery Ratio (PDR)
    run_metrics['pdr'] = run_metrics['success_rate'] * 100

    # Calcular coeficiente de variación para latencia y energía
    run_metrics['latency_cv'] = (run_metrics['latency_std'] / run_metrics['latency_mean'] * 100).round(2)
    run_metrics['energy_cv'] = (run_metrics['energy_std'] / run_metrics['energy_mean'] * 100).round(2)

    # Reset index para tener run_id como columna
    run_metrics = run_metrics.reset_index()

    print(f"Resumen de {len(run_metrics)} ejecuciones:")
    print(run_metrics.describe())

    # 4. Estadísticas Descriptivas entre Runs
    # Estadísticas de las métricas agregadas por run
    summary_stats = run_metrics.describe().round(4)
    print("Estadísticas de las métricas por ejecución:")
    print(summary_stats)

    # Intervalos de confianza del 95%
    confidence_intervals = {}
    for col in ['latency_mean', 'energy_total', 'pdr']:
        mean = run_metrics[col].mean()
        std = run_metrics[col].std()
        n = len(run_metrics)
        ci_lower = mean - 1.96 * (std / np.sqrt(n))
        ci_upper = mean + 1.96 * (std / np.sqrt(n))
        confidence_intervals[col] = (ci_lower, ci_upper)

    print("\nIntervalos de confianza del 95%:")
    for metric, ci in confidence_intervals.items():
        print(f"{metric}: [{ci[0]:.4f}, {ci[1]:.4f}]")


    # 5. Análisis de Variabilidad
    # Prueba de Levene para homogeneidad de varianzas
    levene_latency = stats.levene(*[group['latency_ms'].values for name, group in df.groupby('run_id')])
    levene_energy = stats.levene(*[group['energy_j'].values for name, group in df.groupby('run_id')])

    print(f"Prueba de Levene para latencia: p-value = {levene_latency.pvalue:.6f}")
    print(f"Prueba de Levene para energía: p-value = {levene_energy.pvalue:.6f}")

    # ANOVA de una vía para latencia entre runs
    groups = [group['latency_ms'].values for name, group in df.groupby('run_id')]
    f_stat, p_value = stats.f_oneway(*groups)
    print(f"ANOVA para latencia entre runs: F = {f_stat:.4f}, p = {p_value:.6f}")

    # Coeficiente de variación intraclase (ICC) - simplificado
    def calculate_icc(data):
        """Calcula ICC(1,1) - one-way random effects model"""
        n_runs = len(data)
        n_obs = len(data[0])
        
        SS_total = np.var(np.concatenate(data)) * (n_runs * n_obs - 1)
        SS_within = sum(np.var(group) * (len(group) - 1) for group in data)
        SS_between = SS_total - SS_within
        
        MS_between = SS_between / (n_runs - 1)
        MS_within = SS_within / (n_runs * (n_obs - 1))
        
        icc = (MS_between - MS_within) / (MS_between + (n_obs - 1) * MS_within)
        return max(0, icc)  # ICC no puede ser negativo

    # Ejemplo de cálculo de ICC para latencia (requiere mismo número de observaciones por run)
    icc_latency = calculate_icc(groups)
    print(f"Coeficiente de correlación intraclase (ICC) para latencia: {icc_latency:.4f}")

    # 6. Visualizaciones para Análisis entre Runs
    # Figura 1: Comparación de métricas clave entre runs
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))

    run_metrics['run_num'] = run_metrics['run_id'].str.extract(r'(\d+)').astype(int)

    # Latencia promedio por run
    axes[0,0].bar(run_metrics['run_num'], run_metrics['latency_mean'])
    axes[0,0].set_title('Latencia Promedio por Ejecución')
    axes[0,0].set_ylabel('Latencia (ms)')
    axes[0,0].set_xlabel('Runs')
    axes[0,0].tick_params(axis='x', rotation=45)

    # Energía total por run
    axes[0,1].bar(run_metrics['run_num'], run_metrics['energy_total'])
    axes[0,1].set_title('Energía Total Consumida por Ejecución')
    axes[0,1].set_ylabel('Energía (J)')
    axes[0,1].set_xlabel('Runs')
    axes[0,1].tick_params(axis='x', rotation=45)

    # PDR por run
    axes[0,2].bar(run_metrics['run_num'], run_metrics['pdr'])
    axes[0,2].axhline(y=99.5, color='r', linestyle='--', label='Límite 99.5%')
    axes[0,2].set_title('Packet Delivery Ratio por Ejecución')
    axes[0,2].set_ylabel('PDR (%)')
    axes[0,2].set_xlabel('Runs')
    axes[0,2].tick_params(axis='x', rotation=45)
    axes[0,2].legend()

    df['run_num'] = df['run_id'].str.extract(r'(\d+)').astype(int)

    # Boxplot de latencia por run
    sns.boxplot(data=df, x='run_num', y='latency_ms', ax=axes[1,0])
    axes[1,0].set_title('Distribución de Latencia por Ejecución')
    axes[1,0].set_xlabel('Runs')
    axes[1,0].tick_params(axis='x', rotation=45)

    # Boxplot de energía por run
    sns.boxplot(data=df, x='run_num', y='energy_j', ax=axes[1,1])
    axes[1,1].set_title('Distribución de Energía por Ejecución')
    axes[1,1].set_xlabel('Runs')
    axes[1,1].tick_params(axis='x', rotation=45)

    # Tendencia de métricas a través de las ejecuciones
    axes[1,2].plot(run_metrics['run_num'], run_metrics['latency_mean'], 'o-', label='Latencia')
    axes[1,2].plot(run_metrics['run_num'], run_metrics['energy_total'], 's-', label='Energía')
    axes[1,2].plot(run_metrics['run_num'], run_metrics['pdr'], '^-', label='PDR')
    axes[1,2].set_title('Tendencia de Métricas Principales')
    axes[1,2].set_xlabel('Runs')
    axes[1,2].legend()
    axes[1,2].tick_params(axis='x', rotation=45)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f"analisis_entre_runs_{num_nodes}.png"), dpi=300, bbox_inches='tight')
    plt.show()


    # 7. Tablas Resumen Profesionales

    # Tabla 1: Resumen estadístico de las métricas por run
    summary_table = run_metrics[['latency_mean', 'energy_total', 'pdr', 'latency_cv']].describe()
    print("Tabla 1: Estadísticas descriptivas de las métricas por ejecución")
    print(summary_table.round(4))

    # Tabla 2: Resultados por run (primeras 10 filas)
    print("\nTabla 2: Métricas detalladas por ejecución (primeras 10)")
    print(run_metrics.head(10).round(4))

    # # Exportar a LaTeX para publicación
    # print(run_metrics[['run_id', 'latency_mean', 'energy_total', 'pdr']].head().to_latex(index=False))


    # 8. Análisis de Correlaciones Consistentes

    # Calcular correlaciones para cada run y promediar
    correlation_results = []

    for run in df['run_id'].unique():
        run_data = df[df['run_id'] == run]
        
        corr_latency_distance = run_data['latency_ms'].corr(run_data['distance_m'])
        corr_energy_bits = run_data['energy_j'].corr(run_data['bits_sent'])
        corr_snr_per = run_data['SNR_dB'].corr(run_data['PER'])
        
        correlation_results.append({
            'run_id': run,
            'latency_distance': corr_latency_distance,
            'energy_bits': corr_energy_bits,
            'snr_per': corr_snr_per
        })

    corr_df = pd.DataFrame(correlation_results)
    # avg_correlations = corr_df.mean()
    avg_correlations = corr_df.select_dtypes(include="number").mean()
    # std_correlations = corr_df.std()
    std_correlations = corr_df.select_dtypes(include="number").std()

    print("\nCorrelaciones promedio entre runs:")
    for col in corr_df.columns[1:]:
        print(f"{col}: {avg_correlations[col]:.4f} ± {std_correlations[col]:.4f}")



    # 9. Detección de Valores Atípicos entre Runs
    # Identificar runs con métricas atípicas
    from scipy import stats

    # Calcular z-scores para métricas clave
    for metric in ['latency_mean', 'energy_total', 'pdr']:
        z_scores = stats.zscore(run_metrics[metric])
        outliers = run_metrics[abs(z_scores) > 2]  # |z| > 2 como criterio
        if not outliers.empty:
            print(f"Runs atípicos en {metric}: {outliers['run_id'].tolist()}")

    # 10. Reporte Final de Consistencia
    # Generar reporte de consistencia
    consistency_report = f"""
    REPORTE DE CONSISTENCIA ENTRE {len(run_metrics)} EJECUCIONES
    ================================================

    MÉTRICAS PRINCIPALES:
    - Latencia promedio: {run_metrics['latency_mean'].mean():.2f} ± {run_metrics['latency_mean'].std():.2f} ms
    - Energía total: {run_metrics['energy_total'].mean():.2f} ± {run_metrics['energy_total'].std():.2f} J
    - PDR: {run_metrics['pdr'].mean():.2f} ± {run_metrics['pdr'].std():.2f} %

    CONSISTENCIA ESTADÍSTICA:
    - ANOVA latencia: F = {f_stat:.4f}, p = {p_value:.6f}
    - Coeficiente variación latencia: {run_metrics['latency_cv'].mean():.2f}%
    - Coeficiente variación energía: {run_metrics['energy_cv'].mean():.2f}%

    CORRELACIONES CONSISTENTES:
    - Latencia-Distancia: {avg_correlations['latency_distance']:.4f} ± {std_correlations['latency_distance']:.4f}
    - Energía-Bits: {avg_correlations['energy_bits']:.4f} ± {std_correlations['energy_bits']:.4f}

    CONCLUSIÓN: {'Alta consistencia' if p_value > 0.05 else 'Variabilidad significativa detectada'}
    """

    print(consistency_report)