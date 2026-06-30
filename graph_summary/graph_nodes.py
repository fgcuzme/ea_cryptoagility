import pickle
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import os

## nodes 20 -> run10; nodes 30 -> run20 ; nodes 200 -> run30; 

## output_dir = r'C:\compilables_embed\results_sh5_w0.5_1000m\nodes_500\run_10\save_struct'
# output_dir = r'G:\Mi unidad\PhD_UMalaga\AÑO 7 2026\Utangle_code\results\nodes_30\run_1\save_struct'
output_dir = r'G:\Mi unidad\PhD_UMalaga\AÑO 7 2026\Utangle_code\results\nodes_100_W5_Sh0.5_1000m_per0.30\run_1\save_struct'
os.makedirs(output_dir, exist_ok=True)  # Asegura que la carpeta exista
num_nodes = 100
nodos_save = 'nodos_guardados_1_100.pkl'
nodo_sink = 'sink_guardado_1_100.pkl'

# Cargar los datos de los nodos y el sink
nodos_file_path = os.path.join(output_dir, nodos_save)
sink_file_path = os.path.join(output_dir, nodo_sink)

with open(nodos_file_path, "rb") as f:
    nodos = pickle.load(f)

with open(sink_file_path, "rb") as f:
    sink = pickle.load(f)

# Extraer información relevante
num_nodos = len(nodos)
sink_pos = sink["Position"]  # Posición del sink

# Identificar Cluster Heads (CH) y nodos regulares
CH = [nodo["NodeID"] for nodo in nodos if "ClusterHead" in nodo and nodo["ClusterHead"] == nodo["NodeID"]]
nodos_regulares = [nodo["NodeID"] for nodo in nodos if nodo["NodeID"] not in CH]

# Obtener posiciones de los nodos
pos_nodes = {nodo["NodeID"]: nodo["Position"] for nodo in nodos}

# Crear grafo dirigido (DAG)
G = nx.DiGraph()

# Agregar nodos al grafo
for nodo in nodos:
    G.add_node(nodo["NodeID"], pos=pos_nodes[nodo["NodeID"]])

# Agregar conexiones basadas en la matriz de adyacencia
for nodo in nodos:
    for vecino in nodo["NeighborNodes"]:
        G.add_edge(nodo["NodeID"], vecino)

# Graficar en 3D
fig = plt.figure(figsize=(10, 8))
ax = fig.add_subplot(111, projection='3d')

# Graficar el Sink
ax.scatter(sink_pos[0], sink_pos[1], -sink_pos[2], c='red', s=100, label='Sink')

# Graficar los nodos y diferenciarlos entre CH y sensores normales
for nodo_id, pos in pos_nodes.items():
    if nodo_id in CH:
        ax.scatter(pos[0], pos[1], -pos[2], c='blue', s=100, label='CH' if nodo_id == CH[0] else "")
    else:
        ax.scatter(pos[0], pos[1], -pos[2], c='green', s=50, label='Sensor' if nodo_id == nodos_regulares[0] else "")

# # Dibujar conexiones entre nodos
# for nodo in nodos:
#     nodo_pos = pos_nodes[nodo["NodeID"]]
#     for vecino in nodo["NeighborNodes"]:
#         vecino_pos = pos_nodes[vecino]
#         ax.plot([nodo_pos[0], vecino_pos[0]], 
#                 [nodo_pos[1], vecino_pos[1]], 
#                 [-nodo_pos[2], -vecino_pos[2]], 'k-', alpha=0.5)

# Dibujar conexiones solo de los sensores hacia su CH
for nodo in nodos:
    nodo_id = nodo["NodeID"]
    if "ClusterHead" in nodo and nodo["ClusterHead"] != nodo_id:  # Nodo regular
        ch_id = nodo["ClusterHead"]
        if ch_id in pos_nodes:  # Verificar que el CH existe
            nodo_pos = pos_nodes[nodo_id]
            ch_pos = pos_nodes[ch_id]
            ax.plot([nodo_pos[0], ch_pos[0]], 
                    [nodo_pos[1], ch_pos[1]], 
                    [-nodo_pos[2], -ch_pos[2]], 'k-', alpha=0.5)
            

# Conectar CH al Sink visualmente
for ch in CH:
    ch_pos = pos_nodes[ch]
    ax.plot([ch_pos[0], sink_pos[0]], 
            [ch_pos[1], sink_pos[1]], 
            [-ch_pos[2], -sink_pos[2]], 'r-', linewidth=1.5)

# Agregar etiquetas a los nodos
for nodo_id, (x, y, z) in pos_nodes.items():
    ax.text(x, y, -z, f'{nodo_id}', color='black', fontsize=10)

# Configuraciones del gráfico
ax.set_title(f'Network UANs - {num_nodes} nodes')
ax.set_xlabel('Posición X')
ax.set_ylabel('Posición Y')
ax.set_zlabel('Posición Z')
ax.legend()
plt.grid(True)
# plt.savefig(os.path.join(output_dir, f"network_uans_{num_nodes}.png"), dpi=300, bbox_inches='tight')
plt.savefig(
    os.path.join(output_dir, f"network_uans_{num_nodes}.png"),
    dpi=300,
    bbox_inches='tight',
    transparent=True,
    facecolor='white'
)
plt.show()

