# run_many.py
import os, subprocess, sys
from pathlib import Path

# Tamaños de red
# node_sizes = [20, 50, 100, 200, 300, 400, 500]
# node_sizes = [400, 500, 700, 900, 1000]
node_sizes = [20]

# Parámetros físicos
dim_x = 1000
dim_y = 1000
dim_z = -1000
shipping = 0.5
wind_speed = 5.0

# Parameters sink
sink_pos_x = 500
sink_pos_y = 500
sink_pos_z = 0

# valor PER
per = "0.5"  # aquí defines la variable de entorno "None" or "0.15"

# Construir nombre de escenario
name_scenario = f"{dim_x}m_W{int(wind_speed)}_Sh{shipping}"

# Escenarios EA-CryptoAgility del artículo
# SC1_NORMAL              operación normal
# SC2_LOW_ENERGY          baja energía
# SC3_DEGRADED_CHANNEL    canal degradado
# SC4_HIGH_RISK           ataque/riesgo alto
# SC5_DAG_CONGESTION      congestión DAG
EA_SCENARIOS = [
    "SC1_NORMAL",
    "SC2_LOW_ENERGY",
    "SC3_DEGRADED_CHANNEL",
    "SC4_HIGH_RISK",
    "SC5_DAG_CONGESTION",
]

# Modos de comparación
# 0 = Static U-Tangle baseline
# 1 = EA-CryptoAgility U-Tangle
EA_MODES = [0, 1]

def run_batch(
    # scenario="1000km_W5_Sh0.5",
    scenario = name_scenario,
    runs=1,
    seed0=1337,
    seeds_mode="inc",   # "inc" => seed0, seed0+1,...  | "same" => mismo seed para todos
    ea_modes=None,
    ea_scenarios=None
):
    
    ea_modes = EA_MODES if ea_modes is None else ea_modes
    ea_scenarios = EA_SCENARIOS if ea_scenarios is None else ea_scenarios

    env_base = os.environ.copy()
    env_base["SCENARIO_ID"] = scenario

    for ea_enabled in ea_modes:
        scheme_name = "EA_CryptoAgility" if ea_enabled == 1 else "Static_UTangle"

        for ea_scenario_id in ea_scenarios:

            for size in node_sizes:    
                for i in range(1, runs+1):
                    env = env_base.copy()
                    env["RUN"] = str(i)
                    env["UWSN_SEED"] = str(seed0 if seeds_mode=="same" else (seed0 + i - 1))
                    env["UNSN_NUM_NODES"] = str(size)  # 👈 nuevo parámetro

                    # Activación EA-CryptoAgility
                    env["EA_ENABLED"] = str(ea_enabled)
                    env["EA_SCENARIO_ID"] = ea_scenario_id
                    env["SCHEME_ID"] = scheme_name
                    
                    #run_dir = f"results/nodes_{size}/run_{i}"
                    # Directorio de salida separado por esquema/escenario/nodos/run
                    run_dir = (
                        f"results/{scheme_name}/{ea_scenario_id}/"
                        f"nodes_{size}/run_{i}"
                        )
                    env["OUTPUT_DIR"] = run_dir
                    Path(run_dir).mkdir(parents=True, exist_ok=True)


                    env["PER_VARIABLE"] = str(per)  # aquí defines la variable de entorno "None" or "0.15"
                    
                    # Diametro de la red
                    env["DIM_X"] = str(dim_x)
                    env["DIM_Y"] = str(dim_y)
                    env["DIM_Z"] = str(dim_z)
                    # Ubicación del sink
                    env["SINK_POS_X"] = str(sink_pos_x)
                    env["SINK_POS_Y"] = str(sink_pos_y)
                    env["SINK_POS_Z"] = str(sink_pos_z)
                    # Radio de comunicacion para formar cluster
                    env["RADIO_RANGE"] = "500"

                    # POWER CONSUMPTION MODE TX
                    # env["PC_TX"] = "0.0000005" # value "2.5" or "adaptive"
                    env["PC_TX"] = "adaptive" # value "2.5" or "adaptive"

                    # shipping=0.5, wind_speed_mps=5.0
                    env["SHIPPING"] = str(shipping)
                    env["WIND_SPEED"] = str(wind_speed)

                    # spreading
                    env["SPREADING"] = "1.5"

                    # Energia inicial
                    env["UWSN_ENERGY_INITIAL_J"] = "50.0"

                    print(f">>> NODES={size} RUN={env['RUN']} SEED={env['UWSN_SEED']}")
                    # knobs de rendimiento/registro (ver sección 4)
                    # env.setdefault("UWSN_TANGLE_SAMPLING", "1.0")   # mide todo (o 0.25 para 25%)
                    # env.setdefault("UWSN_TANGLE_BATCH", "64")       # flush CSV cada 64 eventos
                    # env.setdefault("UWSN_TANGLE_RESERVOIR", "1024") # p* cálculos
                    # ejecuta la simulación
                    subprocess.run(["python", "simulation_test1_light.py",
                                    "--output_dir", run_dir], env=env, check=True)
                    # subprocess.run(["./simulation_test1_light_arm",
                    #                 "--output_dir", run_dir], env=env, check=True)

if __name__ == "__main__":

    if os.environ.get("EA_ONLY", "0") == "1":
        ea_modes = [1]
    elif os.environ.get("BASELINE_ONLY", "0") == "1":
        ea_modes = [0]
    else:
        ea_modes = [0, 1]

    scenario_filter = os.environ.get("EA_SCENARIO_ID", "")
    if scenario_filter:
        ea_scenarios = [scenario_filter]
    else:
        ea_scenarios = EA_SCENARIOS

    run_batch(scenario=os.environ.get("SCENARIO_ID", name_scenario),
              runs=int(os.environ.get("RUNS","1")),
              seed0=int(os.environ.get("SEED0","1337")),
              #num_nodes=int(os.environ.get("NUM_NODES", "20")),
              seeds_mode=os.environ.get("SEEDS_MODE","inc"),
              ea_modes=ea_modes,
            #   ea_modes="1",
              ea_scenarios=ea_scenarios
              )


# # bash para linux
# Correr todo: baseline + EA, SC1–SC5
# RUNS=10 python a_run_many.py

# Solo EA-CryptoAgility
# EA_ONLY=1 RUNS=10 python a_run_many.py

# Solo baseline estático
# BASELINE_ONLY=1 RUNS=10 python a_run_many.py

# BASELINE_ONLY=1 RUNS=10 python a_run_many.py
# EA_SCENARIO_ID=SC3_DEGRADED_CHANNEL RUNS=10 python a_run_many.py

# Misma semilla para comparar estrictamente baseline vs EA
# SEEDS_MODE=same RUNS=10 python a_run_many.py

# paper
# SEEDS_MODE=inc RUNS=30 python a_run_many.py

# En Windows PowerShell
# $env:EA_ONLY="1"
# $env:RUNS="10"
# python a_run_many.py

# $env:EA_ONLY="1"
# $env:RUNS="10"
# $env:EA_SCENARIO_ID="SC3_DEGRADED_CHANNEL"
# python a_run_many.py

# Para volver a correr baseline y EA juntos, limpia las variables:
# Remove-Item Env:EA_ONLY
# Remove-Item Env:EA_SCENARIO_ID
# $env:RUNS="10"
# python a_run_many.py

# En CMD de Windows
# set EA_ONLY=1
# set RUNS=10
# python a_run_many.py