import sqlite3
import random, os
# from transmission_logger import log_transmission_event
from energia_dinamica import (calcular_energia_paquete, energy_listen, energy_standby, 
                              calculate_timeout, update_energy_node_tdma, estimate_proc_time_s, 
                              update_energy_standby_others, update_energy_failed_rx, energy_proc_j,
                              OPS_TIME,)
from per_from_link_uan import per_from_link, propagate_with_probability
from transmission_logger_uan import log_event

global VERBOSE

raw_per = os.environ.get("PER_VARIABLE", None)
PER_VARIABLE = float(raw_per) if raw_per not in [None, "None"] else None

# ============================================================
# U-Tangle baseline packet-size model
# ============================================================
#
# Se mantienen tamaños nominales fijos para asegurar
# comparabilidad directa con el baseline U-Tangle:
#
# DATA:
#     protected field = 60 B
#     header          = 10 B
#     total           = 70 B
#
# AGG_DATA:
#     protected field = 92 B
#     header          = 11 B
#     total           = 103 B
#
# EA-CryptoAgility añade posteriormente policy metadata y
# cryptographic proofs sobre estos tamaños base.
# ============================================================
# PER_VARIABLE = None
VERBOSE = False
# PAYLOAD_BITS_SN = 60*8 # 480 bits
# PAYLOAD_BITS_CH = 92*8 # 736 bits

# HEADER_BYTES_SN = 10
# HEADER_BYTES_CH = 11

# BASE_DATA_BYTES = 70
# BASE_AGG_DATA_BYTES = 103

# ============================================================
# Fixed U-Tangle DATA-plane model
# ============================================================

# Ascon-128 v1.2 framing
ASCON_NONCE_BYTES = 16
ASCON_TAG_BYTES = 16

# Complete protected field transmitted in the baseline frame:
# nonce + ciphertext/plaintext-length + authentication tag
PROTECTED_FIELD_SN_BYTES = 60
PROTECTED_FIELD_CH_BYTES = 92

# Protocol headers
HEADER_BYTES_SN = 10
HEADER_BYTES_CH = 11

# Complete baseline acoustic frames
BASE_DATA_BYTES = 70
BASE_AGG_DATA_BYTES = 103

# ============================================================
# Minimal hop-by-hop ACK / ARQ model
# ============================================================
# El ACK se modela como un pequeño frame de control.
# Se permite, por defecto, una única retransmisión DATA.
# El valor puede cambiarse mediante variable de entorno sin
# modificar el código experimental.
# ============================================================
ACK_BITS = 7 * 8
MAX_DATA_RETRIES = int(os.environ.get("UAN_MAX_DATA_RETRIES","1")
)

# ------------------------------------------------------------
# Plaintext actually processed by Ascon
# ------------------------------------------------------------

ASCON_PLAINTEXT_SN_BYTES = (
    PROTECTED_FIELD_SN_BYTES
    - ASCON_NONCE_BYTES
    - ASCON_TAG_BYTES
)

ASCON_PLAINTEXT_CH_BYTES = (
    PROTECTED_FIELD_CH_BYTES
    - ASCON_NONCE_BYTES
    - ASCON_TAG_BYTES
)

assert ASCON_PLAINTEXT_SN_BYTES == 28
assert ASCON_PLAINTEXT_CH_BYTES == 60

# Legacy names retained because the logger currently expects them.
# IMPORTANT: these represent the COMPLETE PROTECTED FIELD,
# not pure application plaintext.
PAYLOAD_BITS_SN = PROTECTED_FIELD_SN_BYTES * 8
PAYLOAD_BITS_CH = PROTECTED_FIELD_CH_BYTES * 8

# helper para completar el plaintext hasta 28B o 60B
def _prepare_nominal_ascon_plaintext(
    plaintext,
    target_bytes,
):
    """
    Convierte el payload de aplicación a bytes y lo completa
    hasta el workload criptográfico nominal usado por U-Tangle.

    DATA SN -> CH:
        target_bytes = 28 B

    AGG CH -> Sink:
        target_bytes = 60 B

    El padding queda protegido por Ascon y no modifica el tamaño
    del frame base, que permanece en 70 B / 103 B.
    """

    if isinstance(plaintext, str):
        payload = plaintext.encode("utf-8")

    elif isinstance(plaintext, bytes):
        payload = plaintext

    else:
        raise TypeError(
            "plaintext must be str or bytes"
        )

    original_length = len(payload)

    if original_length > target_bytes:
        raise ValueError(
            "Application payload exceeds nominal Ascon "
            f"plaintext capacity: {original_length} B > "
            f"{target_bytes} B"
        )

    padded_payload = payload.ljust(
        target_bytes,
        b"\x00"
    )

    return padded_payload, original_length

# Crea la tabla para almacenar las claves compartidas en la BBDD del nodo
def create_shared_keys_table(db_path):

    # Obtener la ruta del directorio donde se encuentra el script actual
    # current_dir = os.path.dirname(os.path.abspath(__file__))
    current_dir = os.getcwd()
    
    # Definir la carpeta donde quieres guardar el archivo (carpeta 'data')
    carpeta_destino = os.path.join(current_dir, 'data')

    # Crea la carpeta en caso de no existir
    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    # Ruta completa del archivo de la base de datos dentro de la carpeta 'data'
    ruta_bbdd = os.path.join(carpeta_destino, db_path)

    conn = sqlite3.connect(ruta_bbdd)
    cursor = conn.cursor()

    # conn = sqlite3.connect(db_path)
    # cursor = conn.cursor()
    
    # Eliminar la tabla si ya existe
    cursor.execute("DROP TABLE IF EXISTS shared_keys")

    # Crear la tabla desde cero
    cursor.execute('''CREATE TABLE shared_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        node_id INTEGER,
                        peer_id INTEGER,
                        shared_key BLOB,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    conn.commit()
    conn.close()

# Obtiene las claves de la BBDD del nodo, con el ID de clave
def get_x25519_keys(db_path, key_id):
    # """Obtiene las claves X25519 de la base de datos usando el ID aleatorio asignado."""
    # conn = sqlite3.connect(db_path)
    # cursor = conn.cursor()

    # Obtener la ruta del directorio donde se encuentra el script actual
    # current_dir = os.path.dirname(os.path.abspath(__file__))
    current_dir = os.getcwd()
    
    # Definir la carpeta donde quieres guardar el archivo (carpeta 'data')
    carpeta_destino = os.path.join(current_dir, 'data')

    # Crea la carpeta en caso de no existir
    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    # Ruta completa del archivo de la base de datos dentro de la carpeta 'data'
    ruta_bbdd = os.path.join(carpeta_destino, db_path)

    conn = sqlite3.connect(ruta_bbdd)
    cursor = conn.cursor()

    cursor.execute("SELECT clave_publica, clave_privada FROM keys_shared_x25519 WHERE id = ?", (key_id,))
    row = cursor.fetchone()
    conn.close()
    return row if row else (None, None)


from cryptography.hazmat.primitives.asymmetric import x25519

# Realiza la derivación de la clave, tomando la clave privada del nodo source y
# la clave publica de nodo destination
def derive_shared_key(x_priv_bytes, peer_x_pub_bytes):
    """Deriva una clave compartida usando X25519."""
    private_key = x25519.X25519PrivateKey.from_private_bytes(x_priv_bytes)
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_x_pub_bytes)
    return private_key.exchange(peer_public_key)


# Almacena la clave compartida en la tabla respectiva
def store_shared_key(db_path, node_id, peer_id, shared_key):
    # """Guarda la clave compartida en la base de datos."""
    # conn = sqlite3.connect(db_path)
    # cursor = conn.cursor()

    # Obtener la ruta del directorio donde se encuentra el script actual
    # current_dir = os.path.dirname(os.path.abspath(__file__))
    current_dir = os.getcwd()
    
    # Definir la carpeta donde quieres guardar el archivo (carpeta 'data')
    carpeta_destino = os.path.join(current_dir, 'data')

    # Crea la carpeta en caso de no existir
    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    # Ruta completa del archivo de la base de datos dentro de la carpeta 'data'
    ruta_bbdd = os.path.join(carpeta_destino, db_path)

    conn = sqlite3.connect(ruta_bbdd)
    cursor = conn.cursor()

    cursor.execute("INSERT INTO shared_keys (node_id, peer_id, shared_key) VALUES (?, ?, ?)",
                   (int(node_id), int(peer_id), shared_key))
    conn.commit()
    conn.close()

# Función para generar claves compartidas desde el soruce al destination
def generate_shared_keys(db_path, node_uw, CH, node_sink):
    """Genera claves compartidas considerando los ID aleatorios asignados a cada nodo."""
    for node in node_uw:
        node_id = node["NodeID"]
        key_id = node["Id_pair_keys_shared"]  # ID de clave aleatoria
        ch_id = node["ClusterHead"]
        # if_node_ch = 0
        
        # Obtner clave del sink
        x_pub_sink = node_sink["PublicKey_shared"]

        # Evitar que el nodo genere una clave con él mismo
        if node_id == ch_id:
            # print(f"⚠️ Nodo {node_id} es un CH y no generará clave consigo mismo.")
            # print(f"⚠️ Nodo {node_id} es un CH...")

            # Obtener claves del nodo y su Cluster Head
            x_pub_node, x_priv_node = get_x25519_keys(db_path, key_id)

            shared_key = derive_shared_key(x_priv_node, x_pub_sink)

            #print("db_path : ", db_path, "node_id : ", node_id, "node_sink[NodeID] : ", node_sink["NodeID"], "shared_key : ", shared_key.hex())
            store_shared_key(db_path, node_id, node_sink["NodeID"], shared_key)
            # print(f"🔐 CH {node_id} generó clave compartida con el Sink", shared_key.hex())
            # if_node_ch = 1
            continue
        # else:
        #     if_node_ch = 2

        # Obtener claves del nodo y su Cluster Head
        x_pub_node, x_priv_node = get_x25519_keys(db_path, key_id)
        ch_key_id = next(n["Id_pair_keys_shared"] for n in node_uw if n["NodeID"] == ch_id)
        x_pub_ch, _ = get_x25519_keys(db_path, ch_key_id)

        # Obtener claves del Sink (única clave)
        # sink_key_id = node_sink["Id_pair_keys_shared"]
        # x_pub_sink, _ = get_x25519_keys(db_path, sink_key_id)

        if x_priv_node and x_pub_ch:

            shared_key = derive_shared_key(x_priv_node, x_pub_ch)

            #print("db_path : ", db_path, "node_id : ", node_id, "ch_id : ", ch_id, "shared_key : ", shared_key.hex())
            store_shared_key(db_path, node_id, ch_id, shared_key)
            # print(f"🔐 Nodo {node_id} generó clave compartida con CH {ch_id}", shared_key.hex())

        #if node_id in CH:  # Si el nodo es un CH, genera clave con el Sink
            

from ascon import encrypt, decrypt

def encrypt_message(shared_key, plaintext):
    """Cifra un mensaje con ASCON-128 usando la clave compartida."""
    key = shared_key[:16]  # ASCON-128 requiere 16 bytes de clave
    nonce = os.urandom(16)
    associated_data = b""
        # Detectar si es str o bytes
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode('utf-8')
    elif isinstance(plaintext, bytes):
        plaintext_bytes = plaintext
    else:
        raise TypeError("El parámetro 'plaintext' debe ser str o bytes")

    ciphertext = encrypt(key, nonce, associated_data, plaintext_bytes, variant="Ascon-128")
    # print("ciphertext : ", ciphertext, " Len : ", len(ciphertext), "nonce : ", nonce, " Len : ", len(nonce))
    return nonce + ciphertext

def decrypt_message(shared_key, encrypted_message):
    """Descifra un mensaje con ASCON-128."""
    key = shared_key[:16]
    nonce, ciphertext = encrypted_message[:16], encrypted_message[16:]
    associated_data = b""

    decrypted = decrypt(key, nonce, associated_data, ciphertext, variant="Ascon-128")

    if decrypted is None:
        return None

    try:
        # Intentar decodificar como texto UTF-8
        return decrypted.decode('utf-8')
    except UnicodeDecodeError:
        # Si no es texto, devolver como binario
        return decrypted


import numpy as np
# from test_throp import propagation_time, compute_path_loss, propagation_time1
from path_loss import compute_path_loss, propagation_time1

# data_packet = {
#     "PacketType": 0x03,           # Identificador de tipo DATA
#     "SourceID": node_id,          # Nodo que envía el paquete
#     "Timestamp": current_time,    # Marca de tiempo local
#     "EncryptedPayload": cipher_text,  # Datos cifrados con Ascon
#     "Tag": tag                    # Tag de autenticación (si no está embebido)
# }

# agg_packet = {
#     "PacketType": 0x04,           # Tipo de paquete agregado
#     "ClusterID": ch_id,           # Identificador del CH
#     "Timestamp": current_time,    # Marca de tiempo de envío
#     "PayloadCount": N,            # Número de paquetes agregados
#     "AggregatedPayload": encrypted_blob  # Cifrado conjunto (JSON/lista cifrada)
# }


### helper
def _resolve_node_ref(nodes, node_ref, label="node"):
    """
    Converts a node reference into a full node dictionary.

    node_ref may be:
      - a node dict
      - a NodeID
      - a list index
    """

    if isinstance(node_ref, dict):
        return node_ref

    node_id_or_index = int(node_ref)

    # 1) Try to resolve by NodeID first
    for n in nodes:
        if isinstance(n, dict) and int(n.get("NodeID", -1)) == node_id_or_index:
            return n

    # 2) Fallback: resolve as list index
    if 0 <= node_id_or_index < len(nodes):
        n = nodes[node_id_or_index]
        if isinstance(n, dict):
            return n

    raise TypeError(
        f"{label} must be a node dict, NodeID, or valid index. "
        f"Received {type(node_ref)} with value {node_ref}"
    )

## Helper
def _ea_select_message_type_from_scenario(scenario, default="TELEMETRY"):
    """
    Selects the EA message type according to the scenario message mix.
    This is mainly useful for SC3_DEGRADED_CHANNEL, where emergency alarms
    should occasionally trigger S4.
    """

    message_mix = getattr(scenario, "message_mix", None)

    if not message_mix:
        return default

    r = random.random()
    acc = 0.0

    for mt, prob in message_mix.items():
        acc += float(prob)

        if r <= acc:
            if hasattr(mt, "value"):
                return mt.value
            return str(mt)

    return default


# Helper
def _ea_checkpoint_due(
    ea_ctx,
    sender_id,
    checkpoint_rule,
    checkpoint_k,
):
    """
    Determina si la transacción ACTUAL debe transportar
    realmente un checkpoint.

    El contador se mantiene dentro de ea_ctx para que forme
    parte exclusivamente del estado de la simulación y no
    dependa de variables globales.

    Reglas:
      IMMEDIATE / STRICT
          -> checkpoint en cada transacción.

      PERIODIC / BATCHED / DELAYED_OR_BATCHED
          -> checkpoint completo cada K transacciones que
             utilizan esa regla.

      Cualquier otra regla
          -> no genera checkpoint.

    IMPORTANTE:
    No se divide el tamaño del hash entre K. Cuando corresponde
    un checkpoint se añaden todos los bytes del hash y se cobra
    una ejecución completa de CHECKPOINT_HASH.
    """
    # --------------------------------------------------------
    # Reglas que generan checkpoint en cada transacción
    # --------------------------------------------------------

    if checkpoint_rule in {
        "IMMEDIATE",
        "STRICT",
    }:
        return True

    # --------------------------------------------------------
    # Reglas que generan checkpoint cada K transacciones
    # --------------------------------------------------------
    if checkpoint_rule not in {
        "PERIODIC",
        "BATCHED",
        "DELAYED_OR_BATCHED",
    }:
        return False

    # --------------------------------------------------------
    # Los contadores se almacenan por nodo y regla.
    #
    # Ejemplo:
    #
    #   (node 7, PERIODIC) -> 1, 2, ..., K
    #
    # Esto evita utilizar un contador global compartido por
    # todos los nodos.
    # --------------------------------------------------------
    counters = ea_ctx.setdefault(
        "_checkpoint_counters",
        {}
    )

    key = (
        int(sender_id),
        str(checkpoint_rule),
    )

    # Número de transacciones que este nodo ha enviado bajo
    # esta regla de checkpoint.
    count = (
        int(counters.get(key, 0))
        + 1
    )

    counters[key] = count

    # --------------------------------------------------------
    # Checkpoint únicamente en:
    #
    #   K, 2K, 3K, ...
    # --------------------------------------------------------
    return (
        count % max(1, int(checkpoint_k))
    ) == 0

# helper
def _simulate_minimal_ack(sender_node, receiver_node, start_pos,
    end_pos, E_schedule, bitrate, distance,
    role_tx, role_rx, dest, effective_per_override=None,
    verbose=False,
):
    """
    Simula un ACK hop-by-hop mínimo.
    Flujo:
        DATA receiver -> ACK -> DATA sender
    El ACK:
      - usa el mismo modelo físico del enlace;
      - tiene tamaño fijo ACK_BITS;
      - no ejecuta criptografía adicional;
      - no constituye una transacción DAG;
      - consume energía TX/RX en nodos sumergidos;
      - el Sink puede transmitir ACK, pero su energía no se
        carga al presupuesto de batería UWSN.

    Returns
    -------
    dict
        success
        energy_j
        latency_s
        per
        tx_energy_j
        rx_energy_j
    """

    # --------------------------------------------------------
    # PHY del ACK.
    # Mismo enlace, pero un frame mucho más corto.
    # --------------------------------------------------------
    (
        ack_per,
        ack_SL_db,
        ack_snr_db,
        ack_EbN0_db,
        ack_ber,
    ) = per_from_link(
        f_khz=20.0,
        distance_m=distance,
        L=ACK_BITS,
        bitrate=bitrate,
    )

    # --------------------------------------------------------
    # Tiempo ACK:
    # dirección inversa:
    #     receiver -> sender
    # --------------------------------------------------------
    (
        ack_prop_ms,
        ack_tx_ms,
        _,
        ack_timeout_s,
    ) = calculate_timeout(
        end_pos,
        start_pos,
        bitrate=bitrate,
        packet_size=ACK_BITS,
        proc_time_s=0.0,
    )

    # --------------------------------------------------------
    # Resultado físico del ACK
    # --------------------------------------------------------
    ack_success = propagate_with_probability(
        per=ack_per,
        override_per=effective_per_override,
    )

    E_ack_tx = 0.0
    E_ack_rx = 0.0

    # ========================================================
    # ACK transmitter
    # ========================================================
    # El ACK lo transmite el receptor original del DATA.
    # SN -> CH:
    #       CH transmite ACK y consume batería.
    # CH -> Sink:
    #       Sink transmite ACK, pero asumimos alimentación
    #       externa y no lo incluimos en energía UWSN.
    # ========================================================
    if (
        dest != "Sink"
        and "ResidualEnergy" in receiver_node
    ):
        e0_ack_tx = float(
            receiver_node["ResidualEnergy"]
        )
        receiver_node = update_energy_node_tdma(
            receiver_node,
            start_pos,
            E_schedule,
            ack_timeout_s,
            "ack",
            role=role_rx,
            action="tx",
            verbose=verbose,
            # ACK sin procesamiento criptográfico adicional.
            t_verif_s=0.0,
            packet_bits=ACK_BITS,
            bitrate=bitrate,
        )

        E_ack_tx = (
            e0_ack_tx
            - float(
                receiver_node["ResidualEnergy"]
            )
        )

    # ========================================================
    # ACK receiver
    # ========================================================
    # El sender DATA queda escuchando el ACK.
    # Si el ACK llega:
    #       RX normal.
    # Si se pierde:
    #       consumo durante timeout/listening.
    # ========================================================
    if "ResidualEnergy" in sender_node:
        e0_ack_rx = float(
            sender_node["ResidualEnergy"]
        )

        if ack_success:
            sender_node = update_energy_node_tdma(
                sender_node,
                end_pos,
                E_schedule,
                ack_timeout_s,
                "ack",
                role=role_tx,
                action="rx",
                verbose=verbose,
                t_verif_s=0.0,
                packet_bits=ACK_BITS,
                bitrate=bitrate,
            )
        else:
            sender_node = update_energy_failed_rx(
                sender_node,
                end_pos,
                ack_timeout_s,
                role=role_tx,
                verbose=verbose,
            )

        E_ack_rx = (
            e0_ack_rx
            - float(
                sender_node["ResidualEnergy"]
            )
        )

    # --------------------------------------------------------
    # Latencia del ACK.
    # ACK válido:
    #       propagation + airtime
    # ACK perdido:
    #       timeout completo
    # --------------------------------------------------------
    if ack_success:
        ack_latency_s = (
            ack_prop_ms
            + ack_tx_ms
        ) / 1000.0
    else:
        ack_latency_s = (
            ack_timeout_s
        )

    return {
    # Resultado físico
    "success": bool(ack_success),

    # PHY
    "per": float(ack_per),
    "snr_db": float(ack_snr_db),
    "ber": float(ack_ber),
    "SL_db": float(ack_SL_db),
    "EbN0_db": float(ack_EbN0_db),

    # Energía
    "energy_j": float(E_ack_tx + E_ack_rx),
    "tx_energy_j": float(E_ack_tx),
    "rx_energy_j": float(E_ack_rx),

    # Timing
    "latency_s": float(ack_latency_s),
    "prop_ms": float(ack_prop_ms),
    "tx_ms": float(ack_tx_ms),
    "timeout_s": float(ack_timeout_s),
}

## transmitir datos
# from ea_cryptoagility.ea_crypto_costs import DEFAULT_OPERATION_COSTS
from ea_cryptoagility.ea_profiles import (
    PROFILE_CONFIG,
    POLICY_META_SIZE_BYTES,
    CRYPTO_PROOF_SIZE_BYTES,
)
from ea_cryptoagility.integration_hooks import (
    attach_policy_to_transaction,
    log_ea_transaction,
    policy_tuple_from_dict,
    estimate_ea_incremental_processing,
    apply_incremental_processing_energy,
)
import math

# helper
def _ea_next_tx_id(
    ea_ctx,
    sender_id,
    receiver_id,
    tx_type,
):
    """
    Genera un identificador determinista para transacciones EA.
    El ID depende únicamente de:
      - run_id
      - seed
      - tipo de transacción
      - sender
      - receiver
      - secuencia del evento
    No utiliza time.time(), por lo que una ejecución repetida
    con la misma configuración y el mismo orden de eventos
    produce los mismos identificadores.
    """
    # --------------------------------------------------------
    # Contador secuencial local al contexto de esta ejecución.
    # --------------------------------------------------------
    seq = (
        int(
            ea_ctx.get(
                "_tx_seq",
                0
            )
        )
        + 1
    )
    ea_ctx["_tx_seq"] = seq

    # --------------------------------------------------------
    # Identificadores del experimento.
    # --------------------------------------------------------
    run_id = ea_ctx.get(
        "run_id",
        "run"
    )

    seed = ea_ctx.get(
        "seed",
        "seed"
    )

    # --------------------------------------------------------
    # Ejemplo:
    #
    # DATA-run03-42-7-2-00000015
    #
    # run03      -> run_id
    # 42         -> seed
    # 7          -> sender
    # 2          -> receiver
    # 00000015   -> secuencia determinista
    # --------------------------------------------------------
    return (
        f"{tx_type}-"
        f"{run_id}-"
        f"{seed}-"
        f"{int(sender_id)}-"
        f"{int(receiver_id)}-"
        f"{seq:08d}"
    )

def transmit_data(RUN_ID, db_path, nodes, sender_node, receiver_node, plaintext, E_schedule,
                  source='SN', dest='CH', ea_ctx=None, bitrate=9200, epoch=None):
    """
    Envío de DATA/AGG entre (SN->CH) y (CH->Sink) con:
    - cifrado ASCON (enc/dec) para medir t_proc,
    - PER por enlace con per_from_link + Bernoulli,
    - energía vía update_energy_node_tdma (incluye t_verif_s),
    - logging canónico con log_event (TX y RX),

    - ACK hop-by-hop y retransmisión DATA acotada;
    - el modelo ARQ es deliberadamente ligero y no representa
    un MAC completo con contention/backoff/RTS/CTS.
    """
    ## helper
    sender_node = _resolve_node_ref(nodes, sender_node, label="sender_node")
    receiver_node = _resolve_node_ref(nodes, receiver_node, label="receiver_node")

    # ============================================================
    # 0) Validate DATA-plane hop
    # ============================================================
    # El modelo DATA revisado admite únicamente:
    #   SN -> CH
    #   CH -> Sink
    # Cualquier otra combinación indica un error de configuración
    # y no debe convertirse silenciosamente en otro tipo de frame.
    # ============================================================
    if source == "SN" and dest == "CH":
        msg_type = type_packet = "data"
        role_tx, role_rx = "SN", "CH"
    elif source == "CH" and dest == "Sink":
        msg_type = type_packet = "agg"
        role_tx, role_rx = "CH", "Sink"
    else:
        raise ValueError(
            "Unsupported DATA-plane hop: "
            f"source={source!r}, dest={dest!r}. "
            "Expected 'SN' -> 'CH' or 'CH' -> 'Sink'."
        )

    # 1) DB path (en /data/)
    current_dir = os.getcwd()
    carpeta_destino = os.path.join(current_dir, 'data')
    os.makedirs(carpeta_destino, exist_ok=True)
    ruta_bbdd = os.path.join(carpeta_destino, db_path)

    # 2) Obtener clave compartida
    conn = sqlite3.connect(ruta_bbdd)
    cursor = conn.cursor()
    sender_id = int(sender_node["NodeID"])
    receiver_id = int(receiver_node["NodeID"])
    cursor.execute("SELECT shared_key, id FROM shared_keys WHERE node_id = ? AND peer_id = ?", (sender_id, receiver_id))
    row = cursor.fetchone()
    conn.close()

    if not row:
        print(f"🚨 No hay clave compartida entre {sender_id} y {receiver_id}")
        return

    shared_key, shared_key_id = row[0], row[1]

    # ============================================================
    # 3) Cifrado/Descifrado
    # ============================================================
    # ============================================================
    # Select nominal Ascon workload
    # ============================================================
    # The acoustic baseline remains fixed:
    #   SN -> CH   : 70 B frame
    #   CH -> Sink : 103 B frame
    # The corresponding Ascon plaintext workloads are:
    #   SN -> CH   : 28 B
    #   CH -> Sink : 60 B
    # ============================================================

    if source == "SN":
        nominal_ascon_plaintext_bytes = (
            ASCON_PLAINTEXT_SN_BYTES
        )
        expected_protected_field_bytes = (
            PROTECTED_FIELD_SN_BYTES
        )
    else:
        nominal_ascon_plaintext_bytes = (
            ASCON_PLAINTEXT_CH_BYTES
        )
        expected_protected_field_bytes = (
            PROTECTED_FIELD_CH_BYTES
        )

    # ------------------------------------------------------------
    # Prepare fixed cryptographic workload
    # ------------------------------------------------------------
    plaintext_for_crypto, application_plaintext_bytes = (
        _prepare_nominal_ascon_plaintext(
            plaintext,
            nominal_ascon_plaintext_bytes,
        )
    )

    # Tamaño útil REAL de aplicación antes de padding,
    # nonce, tag, headers y overhead EA.
    application_payload_bits = (
        int(application_plaintext_bytes)
        * 8
    )

    # ------------------------------------------------------------
    # Functional Ascon encryption
    # ------------------------------------------------------------
    encrypted_msg = encrypt_message(
        shared_key,
        plaintext_for_crypto
    )

    # ============================================================
    # Functional / modeled protected-field consistency
    # ============================================================
    # encrypt_message() devuelve:
    #       nonce || Ascon(ciphertext || tag)
    # Por tanto esperamos exactamente:
    # SN -> CH:
    #       16 B nonce
    #     + 28 B encrypted plaintext
    #     + 16 B authentication tag
    #     = 60 B
    # CH -> Sink:
    #       16 B nonce
    #     + 60 B encrypted plaintext
    #     + 16 B authentication tag
    #     = 92 B
    # Esto garantiza que el workload criptográfico real y el
    # tamaño protegido usado por el modelo PHY coincidan.
    # ============================================================

    functional_ciphertext_bytes = len(encrypted_msg)

    modeled_protected_field_bytes = int(expected_protected_field_bytes)

    if (functional_ciphertext_bytes != modeled_protected_field_bytes):
        raise ValueError(
            "Unexpected Ascon protected-field size: "
            f"{functional_ciphertext_bytes} B != "
            f"{modeled_protected_field_bytes} B "
            f"(source={source})"
        )
    
    # ------------------------------------------------------------
    # Tiempos criptográficos calibrados
    # Raspberry Pi 3 / U-Tangle baseline
    # ------------------------------------------------------------

    t_enc_s = float(
        OPS_TIME["encrypt_s"]
    )

    t_dec_s = float(
        OPS_TIME["descrypt_s"]
    )

    # 4) Geometría + tiempos físicos
    start_pos = np.array(sender_node["Position"])
    end_pos   = np.array(receiver_node["Position"])
    distance  = float(np.linalg.norm(start_pos - end_pos))
    t_prop_s  = float(propagation_time1(start_pos, end_pos, depth=None, region="standard"))


    ## nuevo
    # # 4.1) Tamaño base realmente transmitido: ciphertext ASCON + header
    # if source == 'SN':
    #     header_bytes = 10      # header paquete DATA desde sensores
    # else:
    #     header_bytes = 11      # header paquete agregado CH -> Sink

    # normal_bits_sent = int((len(encrypted_msg) * 8) + (header_bytes * 8))
    # bits_sent = normal_bits_sent

    # ============================================================
    # 4.1) Baseline U-Tangle packet size
    # ============================================================

    if source == "SN":
        header_bytes = HEADER_BYTES_SN
        base_frame_bytes = BASE_DATA_BYTES
    else:
        header_bytes = HEADER_BYTES_CH
        base_frame_bytes = BASE_AGG_DATA_BYTES


    # El campo protegido ya fue determinado y validado
    # inmediatamente después de la operación Ascon.
    modeled_payload_bits = (modeled_protected_field_bytes * 8)

    normal_bits_sent = (modeled_payload_bits + header_bytes * 8)

    assert (
        normal_bits_sent
        == base_frame_bytes * 8
    ), (
        "Inconsistent U-Tangle baseline packet size: "
        f"{normal_bits_sent / 8:.0f} B != "
        f"{base_frame_bytes} B"
    )

    bits_sent = normal_bits_sent
    ################

    tx_ea = None
    ea_enabled = (
        ea_ctx is not None
        and ea_ctx.get("enabled", False)
    )

    # PER preliminar con el tamaño base. Sirve como indicador cross-layer
    # para el motor EA antes de añadir overhead de política.
    per_link_pre, SL_db, snr_db, EbN0_db, ber = per_from_link(
        f_khz=20.0,
        distance_m=distance,
        L=normal_bits_sent,
        bitrate=bitrate
    )

    if ea_enabled:
        scenario = ea_ctx["scenario"]

        # Para los escenarios sintéticos SC1-SC5, usamos el peor caso entre
        # el PER físico preliminar y el PER definido por el escenario.
        # Esto permite que SC3_DEGRADED_CHANNEL active S2/S4 aunque el enlace
        # físico puntual salga demasiado bueno.
        policy_per = max(float(per_link_pre), float(getattr(scenario, "per", 0.0)))

        if epoch is None:
            epoch = 1

        message_type_ea = _ea_select_message_type_from_scenario(
            scenario,
            default="TELEMETRY"
        )

        tx_ea = {
            # --------------------------------------------------------
            # ID determinista:
            #
            # ya no depende del reloj del host.
            # Esto permite comparar eventos entre ejecuciones con la
            # misma seed.
            # --------------------------------------------------------
            "ID": _ea_next_tx_id(
                ea_ctx=ea_ctx,
                sender_id=sender_id,
                receiver_id=receiver_id,
                tx_type=(
                    "DATA"
                    if source == "SN"
                    else "AGG"
                ),
            ),
            "Source":
                sender_id,
            "Type":
                "DATA"
                if source == "SN"
                else "AGG",
            "message_type":
                message_type_ea,
            "Payload":
                plaintext
                if isinstance(plaintext, str)
                else str(plaintext),
            "ApprovedTx": [],
        }

        tx_ea = attach_policy_to_transaction(
            tx=tx_ea,
            node=sender_node,
            epoch=epoch,
            key=ea_ctx["policy_key"],
            per=policy_per,
            retransmission_rate=scenario.retransmission_rate,
            dag_load=scenario.dag_load,
            security_risk=scenario.security_risk,
            invalid_signature_rate=scenario.invalid_signature_rate,
            downgrade_detected=scenario.downgrade_detected,
            replay_detected=scenario.replay_detected,
            suspicious_identity=scenario.suspicious_identity,
        )

        ea_cost = tx_ea.setdefault("ea_cost", {})

        # ============================================================
        # Policy-metadata size consistency
        # ============================================================
        # ea_profiles.py is the canonical source for the modeled
        # policy-metadata size.
        # ============================================================
        policy_meta_bytes = int(
            POLICY_META_SIZE_BYTES
        )

        initial_policy_meta_bytes = (
            ea_cost.get(
                "policy_meta_bytes",
                None
            )
        )

        if (
            initial_policy_meta_bytes is not None
            and int(initial_policy_meta_bytes)
                != policy_meta_bytes
        ):
            raise ValueError(
                "Inconsistent policy metadata size: "
                f"integration_hooks={initial_policy_meta_bytes} B, "
                f"ea_profiles={policy_meta_bytes} B"
            )

  
        ## Agregado
                # =====================================================
        # R1: Profile-dependent overhead
        # =====================================================

        policy = policy_tuple_from_dict(
            tx_ea["Policy"]
        )

        checkpoint_rule = (
            policy.checkpoint_rule.value
        )

        K_PERIODIC = int(
            os.environ.get(
                "EA_CHECKPOINT_K_PERIODIC",
                "10"
            )
        )

        K_BATCHED = int(
            os.environ.get(
                "EA_CHECKPOINT_K_BATCHED",
                "25"
            )
        )

        K_DELAYED = int(
            os.environ.get(
                "EA_CHECKPOINT_K_DELAYED",
                "30"
            )
        )

        # -----------------------------------------------------
        # Checkpoint scheduling
        # -----------------------------------------------------
        #
        # El checkpoint se modela como un EVENTO REAL.
        #
        # Ya no usamos:
        #
        #       checkpoint_amortization = 1 / K
        #
        # para reducir artificialmente el tamaño del hash.
        #
        # En su lugar:
        #
        #       checkpoint_due = False -> 0 B de hash
        #       checkpoint_due = True  -> hash completo
        #
        # Esto permite que packet size, airtime, PER y energía
        # reflejen correctamente las transacciones individuales.
        # -----------------------------------------------------
        if checkpoint_rule in {
            "IMMEDIATE",
            "STRICT",
        }:
            checkpoint_k = 1

        elif checkpoint_rule == "PERIODIC":

            checkpoint_k = max(
                1,
                K_PERIODIC
            )

        elif checkpoint_rule == "BATCHED":

            checkpoint_k = max(
                1,
                K_BATCHED
            )

        elif checkpoint_rule == "DELAYED_OR_BATCHED":

            checkpoint_k = max(
                1,
                K_DELAYED
            )

        else:
            # No existe una periodicidad activa.
            checkpoint_k = 0

        # -----------------------------------------------------
        # ¿Esta transacción concreta lleva checkpoint?
        # -----------------------------------------------------
        checkpoint_due = _ea_checkpoint_due(
            ea_ctx=ea_ctx,
            sender_id=sender_id,
            checkpoint_rule=checkpoint_rule,
            checkpoint_k=checkpoint_k,
        )

        # -----------------------------------------------------
        # El estimador existente recibe un factor.
        #
        # Antes este factor podía ser 1/K.
        # Desde R1 lo usamos como indicador de evento:
        #
        #       1.0 -> ejecutar un checkpoint completo
        #       0.0 -> no ejecutar checkpoint
        #
        # Conservamos el nombre del argumento en
        # estimate_ea_incremental_processing() para no romper su API.
        # -----------------------------------------------------
        checkpoint_factor = (
            1.0
            if checkpoint_due
            else 0.0
        )

        # -----------------------------------------------------
        # Rekey must be an ACTUAL event, not automatically
        # inferred from the profile.
        #
        # Later this will be controlled by the revised
        # stateful policy engine.
        # -----------------------------------------------------
        rekey_triggered = bool(
            ea_ctx.get(
                "rekey_triggered",
                False
            )
        )

        # -----------------------------------------------------
        # Packet overhead
        #
        # encrypted_msg already contains the ASCON ciphertext
        # and authentication tag. Therefore ASCON_TAG must NOT
        # be added again here.
        # -----------------------------------------------------
        cfg = PROFILE_CONFIG[
            policy.profile_id
        ]

        extra_proof_bytes = 0

        if cfg.get(
            "requires_signature",
            False
        ):
            extra_proof_bytes += (
                CRYPTO_PROOF_SIZE_BYTES[
                    "ED25519_SIGNATURE"
                ]
            )

        if (
            cfg.get("requires_rekey", False)
            and rekey_triggered
        ):
            extra_proof_bytes += (
                CRYPTO_PROOF_SIZE_BYTES[
                    "X25519_PUBLIC_KEY"
                ]
            )

        checkpoint_hash_bytes = (
            CRYPTO_PROOF_SIZE_BYTES[
                "CHECKPOINT_HASH"
            ]
        )

        # -----------------------------------------------------
        # Tamaño del checkpoint en el frame físico
        # -----------------------------------------------------
        #
        # Si existe checkpoint en ESTA transacción, añadimos el
        # hash completo. No existe tamaño fraccionario.
        # -----------------------------------------------------
        if checkpoint_due:
            extra_proof_bytes += (
                checkpoint_hash_bytes
            )

        ea_overhead_bytes = (
            policy_meta_bytes
            + extra_proof_bytes
        )

        ea_overhead_bits = (
            8 * ea_overhead_bytes
        )

        bits_sent = (
            normal_bits_sent
            + ea_overhead_bits
        )


        # -----------------------------------------------------
        # Sender EA incremental processing
        #
        # ASCON encryption is excluded because it is already
        # charged by update_energy_node_tdma(t_verif_s=t_enc_s).
        # -----------------------------------------------------

        sender_incremental = \
            estimate_ea_incremental_processing(
                policy,
                side="sender",
                # El parámetro conserva su nombre por compatibilidad,
                # pero ahora recibe 0.0 o 1.0 según exista realmente
                # checkpoint en ESTA transacción.
                checkpoint_amortization=
                    checkpoint_factor,
                checkpoint_input_bytes=256,
                rekey_triggered=
                    rekey_triggered,
                already_accounted_ops={
                    "ASCON_AEAD_ENC"
                },
            )

        ea_cost = tx_ea.setdefault(
            "ea_cost",
            {}
        )

        ### ea_cost.update #1
        ea_cost.update({
            # campos adicionales
            "source_role":
                source,

            "destination_role":
                dest,

            "ascon_nonce_bytes":
                ASCON_NONCE_BYTES,

            "ascon_tag_bytes":
                ASCON_TAG_BYTES,

            # ========================================================
            # FRAME / SIZE INFORMATION
            # ========================================================

            # Tamaño de aplicación antes del padding nominal.
            "application_plaintext_bytes":
                application_plaintext_bytes,

            # Workload plaintext realmente procesado por Ascon.
            #
            # SN -> CH   = 28 B
            # CH -> Sink = 60 B
            "nominal_ascon_plaintext_bytes":
                nominal_ascon_plaintext_bytes,

            # Resultado funcional:
            #
            # nonce + ciphertext + tag
            #
            # SN -> CH   = 60 B
            # CH -> Sink = 92 B
            "functional_ciphertext_bytes":
                functional_ciphertext_bytes,

            # Campo protegido utilizado por el modelo.
            # Debe coincidir exactamente con el valor anterior.
            "modeled_protected_field_bytes":
                modeled_protected_field_bytes,

            # Frame U-Tangle antes de añadir EA.
            #
            # DATA = 70 B
            # AGG  = 103 B
            "modeled_baseline_frame_bytes":
                base_frame_bytes,

            "header_bytes":
                header_bytes,

            # Tamaño base en bits.
            "normal_bits_sent":
                normal_bits_sent,


            # ========================================================
            # EA FRAME OVERHEAD
            # ========================================================

            "policy_meta_bytes":
                policy_meta_bytes,

            "crypto_proof_bytes":
                extra_proof_bytes,

            "ea_overhead_bits":
                ea_overhead_bits,

            # Tamaño realmente utilizado por:
            #
            #   PER
            #   airtime
            #   TX energy
            #   RX energy
            "effective_bits_sent":
                bits_sent,

            "tx_size_bytes":
                int(
                    math.ceil(
                        bits_sent / 8.0
                    )
                ),

            # ========================================================
            # CHECKPOINT / REKEY EVENT
            # ========================================================

            "checkpoint_k":
                checkpoint_k,

            "checkpoint_due":
                checkpoint_due,

            # Legacy fields kept temporarily
            "checkpoint_amortization_k":
                checkpoint_k,

            "checkpoint_amortization":
                checkpoint_factor,

            "rekey_triggered":
                rekey_triggered,

            # ========================================================
            # EA SENDER PROCESSING
            # ========================================================

            "ea_sender_incremental_time_ms":
                float(
                    sender_incremental[
                        "incremental_processing_time_ms"
                    ]
                ),

            # IMPORTANTE:
            # Ésta es la energía calculada por el modelo antes de
            # descontarla de ResidualEnergy.
            "ea_sender_incremental_modeled_energy_mj":
                float(
                    sender_incremental[
                        "incremental_processing_energy_mj"
                    ]
                ),

            "sender_incremental_ops":
                sender_incremental[
                    "incremental_operation_counts"
                ],
        })
        ####

    # Tiempo de transmisión y PER final con el tamaño realmente usado.
    t_tx_s = bits_sent / float(bitrate)

    per_link, SL_db, snr_db, EbN0_db, ber = per_from_link(
        f_khz=20.0,
        distance_m=distance,
        L=bits_sent,
        bitrate=bitrate
    )

    ## incluir también el procesamiento EA
    allow_per_override = bool(
    ea_ctx is not None
    and ea_ctx.get(
        "allow_per_override",
        False
    )
    )

    effective_per_override = (
    PER_VARIABLE
    if allow_per_override
    else None
    )

    # ============================================================
    # Physical channel outcome
    # ============================================================
    # IMPORTANTE:
    # channel_success representa únicamente el resultado del
    # canal acústico:
    #       True  -> el frame llegó físicamente
    #       False -> el frame se perdió en el canal
    # Todavía NO realizamos aquí el descifrado Ascon.
    # El procesamiento RX se realizará más adelante, dentro del
    # bloque específico del receptor.
    #
    # Esto evita:
    #   - ejecutar decrypt dos veces;
    #   - confundir pérdida física con rechazo criptográfico;
    #   - contabilizar incorrectamente energía de procesamiento.
    # ============================================================
    channel_success = propagate_with_probability(
        per=per_link,
        override_per=effective_per_override,
    )

    # ------------------------------------------------------------
    # Resultado inicial.
    # Si el canal entrega el paquete, inicialmente consideramos
    # que el frame está disponible para procesamiento.
    # Posteriormente la verificación AEAD puede hacer que:
    #       success = False
    # aunque:
    #       channel_success = True
    # ------------------------------------------------------------
    success = channel_success

    # ------------------------------------------------------------
    # packet_lost representa exclusivamente pérdida acústica.
    # Una autenticación Ascon fallida NO debe convertirse en una
    # pérdida de canal.
    # ------------------------------------------------------------
    p_lost = not channel_success

    # ------------------------------------------------------------
    # Bits recibidos físicamente.
    # Si más adelante falla la autenticación, bits_rcv puede
    # cambiarse a 0 para representar que el paquete no fue
    # aceptado por la capa superior.
    # ------------------------------------------------------------
    bits_rcv = (
        bits_sent
        if channel_success
        else 0
    )

    # ------------------------------------------------------------
    # Indica si el receptor llegó realmente a ejecutar Ascon DEC.
    # Es importante para energía:
    # aunque la autenticación falle, el intento de descifrado
    # consume procesamiento.
    # ------------------------------------------------------------
    rx_decrypt_attempted = False

    sender_ea_proc_s = (
    float(
        tx_ea.get(
            "ea_cost", {}
        ).get(
            "ea_sender_incremental_time_ms",
            0.0
        )
    )/1000.0
    if ea_enabled
    else 0.0
    )
    sender_total_proc_s = (t_enc_s + sender_ea_proc_s)
    #####

    # 6) Timeout y energía TX (incluye t_proc del emisor = cifrado)
    #    Usamos tu calculate_timeout con proc_time_s=t_enc_s para que el modelo de tiempo sea coherente
    lat_prop_ms, lat_tx_ms, lat_proc_ms, timeout_s = calculate_timeout(start_pos, end_pos, bitrate=bitrate,
                                                                       packet_size=bits_sent, proc_time_s=sender_total_proc_s)
    # E en TX (emisor)
    e0_tx = float(sender_node["ResidualEnergy"])

    sender_node = update_energy_node_tdma(sender_node, end_pos, E_schedule, timeout_s,
                                          type_packet, role=role_tx, action="tx", verbose=VERBOSE,
                                          # Base U-Tangle processing only:
                                          t_verif_s=t_enc_s,
                                          # Real transmitted size:
                                          packet_bits=bits_sent,
                                          bitrate=bitrate,)
    E_tx = e0_tx - float(sender_node["ResidualEnergy"])

    # Descontar procesamiento incremental EA del sender
    # Por defecto, Static U-Tangle:
    E_ea_sender = 0.0 # valor en joules
    E_tx_total = E_tx

    # EA-CryptoAgility:
    # ------------------------------------------------------------
    # EA-CryptoAgility sender incremental processing
    # ------------------------------------------------------------
    if ea_enabled and tx_ea is not None:
        # Energía solicitada por el modelo de procesamiento.
        sender_inc_mj = float(
            tx_ea["ea_cost"].get(
                "ea_sender_incremental_modeled_energy_mj",
                0.0
            )
        )

        # Energía efectivamente descontada de ResidualEnergy.
        # Return value is in joules.
        E_ea_sender = (
            apply_incremental_processing_energy(
                sender_node,
                sender_inc_mj
            )
        )

        E_tx_total = (
            E_tx
            + E_ea_sender
        )

        # Guardar la energía realmente contabilizada [mJ].
        tx_ea["ea_cost"][
            "ea_sender_incremental_energy_mj"
        ] = (
            E_ea_sender * 1000.0
        )
    ###

    # 7) Log TX (emisor)
    log_event(
        run_id=RUN_ID, phase="data", module="ascon", msg_type=f"DATA:{msg_type}:TX",
        sender_id=sender_id, receiver_id=receiver_id, cluster_id=sender_node.get("ClusterHead"),
        start_pos=start_pos, end_pos=end_pos,
        bits_sent=bits_sent, bits_received=bits_rcv, payload_bits=application_payload_bits,
        success=success, packet_lost=p_lost,
        energy_event_type='tx', energy_j=E_tx_total,
        residual_sender=sender_node["ResidualEnergy"], residual_receiver=0 if dest == 'Sink' else receiver_node["ResidualEnergy"],
        bitrate=bitrate, freq_khz=20,
        lat_prop_ms=t_prop_s*1000.0, lat_tx_ms=t_tx_s*1000.0, lat_proc_ms=sender_total_proc_s*1000.0,
        # lat_prop_ms=lat_prop_ms, lat_tx_ms=lat_tx_ms, lat_proc_ms=t_enc_s*1000.0,
        snr_db=snr_db, per=per_link, lat_dag_ms=0.0, SL_db=SL_db, EbN0_db=EbN0_db, BER=ber
    )

    # ## registro evento ea
    # if ea_ctx is not None and ea_ctx.get("enabled", False) and tx_ea is not None:
    #     tx_ea["ea_state"]["snr_db"] = snr_db

    #     log_ea_transaction(
    #         logger=ea_ctx["logger"],
    #         run_id=ea_ctx["run_id"],
    #         seed=ea_ctx["seed"],
    #         scenario_id=ea_ctx["scenario_id"],
    #         tx=tx_ea,
    #         latency_ms=(t_prop_s + t_tx_s + t_enc_s) * 1000.0,
    #         pdr=1.0 if success else 0.0,
    #         downgrade_injected=ea_ctx["scenario"].downgrade_detected,
    #         invalid_policy_meta=False,
    #         invalid_tx_rejected=False,
    #     )
    # ###

    # Se actualiza la energia de los demas nodos
    active_ids = [sender_id, receiver_id]
    active_cluster_id = sender_node["ClusterHead"]
    nodes = update_energy_standby_others(nodes, active_ids, active_cluster_id,
                                         timeout_s, verbose=VERBOSE)


    # ============================================================
    # 8) Si el paquete llega: energía RX + descifrado + EA policy
    # ============================================================

    # ------------------------------------------------------------
    # Valores por defecto.
    # Esto garantiza que todas las variables existan tanto en:
    #   - Static U-Tangle
    #   - EA-CryptoAgility
    #   - paquete recibido
    #   - paquete perdido
    #   - CH
    #   - Sink
    # ------------------------------------------------------------

    E_rx = 0.0                  # J: evento RX base U-Tangle
    E_ea_receiver = 0.0         # J: procesamiento incremental EA
    t_proc_rx_s = 0.0           # s: Ascon decrypt base
    receiver_ea_proc_s = 0.0    # s: procesamiento adicional EA
    receiver_incremental = None
    decrypted_msg = None

    # ============================================================
    # El frame llegó físicamente al receptor
    # ============================================================
    if channel_success:
        # --------------------------------------------------------
        # El receptor ejecutará Ascon decrypt/authentication.
        # --------------------------------------------------------
        rx_decrypt_attempted = True
        t_proc_rx_s = t_dec_s

        # --------------------------------------------------------
        # Operación criptográfica funcional.
        # El tiempo utilizado por la simulación NO se mide aquí.
        # t_dec_s proviene de la calibración Raspberry Pi 3.
        # --------------------------------------------------------
        decrypted_msg = decrypt_message(shared_key, encrypted_msg)

        # --------------------------------------------------------
        # Rechazo criptográfico.
        # El paquete llegó por el canal, por tanto:
        #       channel_success = True
        #       p_lost          = False
        # pero puede no ser aceptado:
        #       success = False
        # Esto será importante posteriormente para las campañas
        # de tampering y autenticación.
        # --------------------------------------------------------
        if decrypted_msg is None:
            success = False
            # No se entrega payload válido a capas superiores.
            bits_rcv = 0

        # --------------------------------------------------------
        # Procesamiento adicional EA-CryptoAgility
        # --------------------------------------------------------
        # Se ejecuta únicamente cuando:
        #   1. el frame llegó físicamente;
        #   2. Ascon lo aceptó;
        #   3. EA-CryptoAgility está habilitado.
        # IMPORTANTE:
        # ASCON_AEAD_DEC se excluye del coste EA porque ya está
        # contabilizado en el baseline U-Tangle mediante:
        #       update_energy_node_tdma(
        #           ...,
        #           t_verif_s=t_proc_rx_s
        #       )
        # De esta forma evitamos doble contabilización.
        # --------------------------------------------------------
        if (
            success
            and ea_enabled
            and tx_ea is not None
        ):

            receiver_incremental = (
                estimate_ea_incremental_processing(
                    policy,
                    side="receiver",
                    # ------------------------------------------------
                    # El receiver procesa exactamente el mismo
                    # checkpoint transportado por el sender.
                    # checkpoint_factor:
                    #       0.0 -> no existe checkpoint
                    #       1.0 -> checkpoint completo
                    # ------------------------------------------------
                    checkpoint_amortization=
                        checkpoint_factor,

                    # Provisional hasta cerrar el tamaño real del
                    # material serializado usado como checkpoint.
                    checkpoint_input_bytes=256,

                    # Solo se incluyen X25519/HKDF si realmente
                    # ocurrió un evento de rekey.
                    rekey_triggered=
                        rekey_triggered,

                    # Ascon DEC pertenece al baseline.
                    already_accounted_ops={
                        "ASCON_AEAD_DEC"
                    },
                )
            )


            # --------------------------------------------------------
            # Tiempo adicional EA en el receptor.
            # estimate_ea_incremental_processing() devuelve ms;
            # aquí se convierte a segundos para calculate_timeout()
            # y para la latencia total del evento.
            # --------------------------------------------------------
            receiver_ea_proc_s = (
                float(receiver_incremental["incremental_processing_time_ms"]
                )
                / 1000.0
            )

            # ========================================================
            # GUARDAR RESULTADOS LÓGICOS DEL PROCESAMIENTO EA
            # ========================================================
            # ESTE ES EL BLOQUE QUE DEBES AÑADIR AQUÍ.
            # Debe estar FUERA de:
            #       if dest != "Sink"
            # porque tanto un CH como el Sink ejecutan conceptualmente
            # la verificación EA.
            # Para el Sink:
            #       tiempo -> sí se contabiliza
            #       operaciones -> sí se contabilizan
            #       energía de batería UWSN -> no se contabiliza
            #
            # Esto permite incluir el tiempo de verificación del Sink
            # sin cargar esa energía al presupuesto de los nodos
            # sumergidos.
            # ========================================================
            ea_cost = tx_ea.setdefault(
                "ea_cost",
                {}
            )

            # ea_cost.update #2
            ea_cost.update({
                # Tiempo computacional modelado en el receiver.
                "ea_receiver_incremental_time_ms":
                    float(receiver_incremental["incremental_processing_time_ms"]
                    ),

                # Operaciones realizadas:
                #
                #   POLICY_MAC_VERIFY
                #   CHECKPOINT_HASH
                #   ED25519_VERIFY
                #   X25519/HKDF
                #   ...
                #
                # según el perfil/evento.
                "receiver_incremental_ops":
                    receiver_incremental["incremental_operation_counts"],

                # ----------------------------------------------------
                # Energía TEÓRICA del procesamiento receiver.
                # Este campo describe cuánto costaría la operación
                # utilizando P_PROC de la plataforma calibrada.
                # No significa necesariamente energía descontada de
                # la batería de la red, porque el Sink se considera
                # externamente alimentado.
                # ----------------------------------------------------

                "ea_receiver_incremental_modeled_energy_mj":
                    float(receiver_incremental["incremental_processing_energy_mj"]),
            })


        # --------------------------------------------------------
        # Tiempo total de procesamiento observado en RX
        # Esto afecta a la LATENCIA.
        # Sin embargo, update_energy_node_tdma recibirá únicamente
        # t_dec_s para no volver a cobrar la energía EA.
        # --------------------------------------------------------
        receiver_total_proc_s = (
            t_proc_rx_s
            + receiver_ea_proc_s
        )

        # --------------------------------------------------------
        # Timeout RX usando:
        #   - tamaño REAL transmitido
        #   - procesamiento base
        #   - procesamiento incremental EA
        # --------------------------------------------------------
        _, _, _, timeout_rx_s = calculate_timeout(
            start_pos,
            end_pos,
            bitrate=bitrate,
            packet_size=bits_sent,
            proc_time_s=receiver_total_proc_s,
        )
        # --------------------------------------------------------
        # Receptor normal
        # --------------------------------------------------------
        if dest != "Sink":
            # Energía antes del evento RX
            e0_rx = float(
                receiver_node["ResidualEnergy"]
            )
            # ----------------------------------------------------
            # U-Tangle base:
            # Aquí se contabiliza:
            #   - RX acústico
            #   - tiempo/passive/listen según el modelo
            #   - ASCON decrypt mediante t_verif_s=t_dec_s
            # NO incluimos todavía procesamiento EA.
            # ----------------------------------------------------
            receiver_node = update_energy_node_tdma(
                receiver_node,
                start_pos,
                E_schedule,
                timeout_rx_s,
                type_packet,
                role=role_rx,
                action="rx",
                verbose=VERBOSE,
                # Solo procesamiento BASE:
                t_verif_s=t_proc_rx_s,
                # Tamaño real del frame:
                packet_bits=bits_sent,
                bitrate=bitrate,
            )

            # Energía RX base realmente descontada
            E_rx = (
                e0_rx
                - float(
                    receiver_node["ResidualEnergy"]
                )
            )

            # ----------------------------------------------------
            # Descontar procesamiento incremental EA
            # ----------------------------------------------------
            # Este bloque está dentro de:
            #       if dest != "Sink"
            # por tanto aquí sí estamos trabajando con un nodo
            # sumergido cuya ResidualEnergy forma parte del
            # presupuesto energético de la UWSN.
            # ----------------------------------------------------
            if receiver_incremental is not None:
                # Energía modelada por ea_crypto_costs.py [mJ]
                receiver_inc_mj = float(receiver_incremental["incremental_processing_energy_mj"]
                )

                # --------------------------------------------------------
                # Descontar físicamente esa energía de ResidualEnergy.
                # La función devuelve J realmente descontados.
                # --------------------------------------------------------
                E_ea_receiver = (
                    apply_incremental_processing_energy(
                        receiver_node,
                        receiver_inc_mj,
                    )
                )

                # --------------------------------------------------------
                # Registrar la energía REAL contabilizada en la batería
                # del nodo.
                # time y operations ya fueron guardados anteriormente.
                # --------------------------------------------------------
                if tx_ea is not None:
                    tx_ea.setdefault(
                        "ea_cost",
                        {}
                    )[
                        "ea_receiver_incremental_energy_mj"
                    ] = (
                        E_ea_receiver * 1000.0
                    )

        # --------------------------------------------------------
        # Sink
        # --------------------------------------------------------
        # El Sink sí ejecutó:
        #   - ASCON verification
        #   - EA policy verification
        # y por tanto esos tiempos/operaciones aparecen en el log.
        # Sin embargo se asume que el Sink está externamente
        # alimentado, por lo que su energía no se carga al
        # presupuesto de batería de la UWSN.
        # --------------------------------------------------------
        else:
            E_rx = 0.0
            E_ea_receiver = 0.0

            if (
                tx_ea is not None
                and receiver_incremental is not None
            ):
                tx_ea.setdefault(
                    "ea_cost",
                    {}
                )[
                    "ea_receiver_incremental_energy_mj"
                ] = 0.0

        # --------------------------------------------------------
        # Energía total correspondiente al receptor
        #
        # E_rx ya incluye procesamiento base.
        # E_ea_receiver contiene SOLO procesamiento nuevo EA.
        # --------------------------------------------------------
        E_rx_total = (
            E_rx
            + E_ea_receiver
        )

        # ========================================================
        # 9) Log RX
        # ========================================================
        log_event(
            run_id=RUN_ID,
            phase="data",
            module="ascon",
            msg_type=f"DATA:{msg_type}:RX",
            sender_id=sender_id,
            receiver_id=receiver_id,
            cluster_id=(
                receiver_node.get("ClusterHead")
                if dest != "Sink"
                else sender_node.get("ClusterHead")
            ),
            start_pos=start_pos,
            end_pos=end_pos,
            bits_sent=bits_sent,
            bits_received=bits_rcv,
            payload_bits=application_payload_bits,
            success=success,
            packet_lost=p_lost,
            # IMPORTANTE:
            # Para el log general usamos consumo RX real total:
            # baseline + incremental EA.
            energy_event_type="rx",
            energy_j=E_rx_total,
            residual_sender=
                sender_node["ResidualEnergy"],
            residual_receiver=(
                0
                if dest == "Sink"
                else receiver_node["ResidualEnergy"]
            ),

            bitrate=bitrate,
            freq_khz=20,

            lat_prop_ms=
                t_prop_s * 1000.0,

            lat_tx_ms=
                t_tx_s * 1000.0,

            # Procesamiento RX completo:
            lat_proc_ms=
                receiver_total_proc_s * 1000.0,

            snr_db=snr_db,
            per=per_link,
            lat_dag_ms=0.0,
            SL_db=SL_db,
            EbN0_db=EbN0_db,
            BER=ber,
        )

    # ============================================================
    # Paquete perdido
    # ============================================================
    else:
        # No hay ASCON decrypt válido ni policy verification
        t_proc_rx_s = 0.0
        receiver_ea_proc_s = 0.0
        E_ea_receiver = 0.0

        if (
            dest != "Sink"
            and "ResidualEnergy" in receiver_node
        ):
            # ----------------------------------------------------
            # IMPORTANTE:
            # Aunque el paquete se pierda, el receptor sí consume
            # energía escuchando/esperando el paquete.
            #
            # Por tanto, NO debemos poner E_rx=0 después.
            # ----------------------------------------------------
            e0_failed_rx = float(
                receiver_node["ResidualEnergy"]
            )

            receiver_node = update_energy_failed_rx(
                receiver_node,
                start_pos,
                timeout_s,
                role=role_rx,
                verbose=VERBOSE,
            )

            E_rx = (
                e0_failed_rx
                - float(
                    receiver_node["ResidualEnergy"]
                )
            )
      
        else:
            E_rx = 0.0

        log_event(
            run_id=RUN_ID,
            phase="data",
            module="ascon",
            msg_type=f"DATA:{msg_type}:RX",
            sender_id=sender_id,
            receiver_id=receiver_id,
            cluster_id=(
                receiver_node.get("ClusterHead")
                if dest != "Sink"
                else sender_node.get("ClusterHead")
            ),
            start_pos=start_pos,
            end_pos=end_pos,
            bits_sent=bits_sent,
            bits_received=0,
            payload_bits=application_payload_bits,
            success=False,
            packet_lost=True,
            energy_event_type="rx",
            energy_j=E_rx,
            residual_sender=
                sender_node["ResidualEnergy"],
            residual_receiver=(
                0
                if dest == "Sink"
                else receiver_node["ResidualEnergy"]
            ),
            bitrate=bitrate,
            freq_khz=20,
            lat_prop_ms=t_prop_s * 1000.0,
            lat_tx_ms=t_tx_s * 1000.0,
            lat_proc_ms=0.0,
            snr_db=snr_db,
            per=per_link,
            lat_dag_ms=0.0,
            SL_db=SL_db,
            EbN0_db=EbN0_db,
            BER=ber,
        )

        E_rx_total = E_rx
    ##################################


    # ============================================================
    # 9.5) Minimal hop-by-hop ACK / retry
    # ============================================================
    #
    # Modelo ARQ simplificado:
    #   DATA -> ACK
    # Si:
    #   - DATA se pierde físicamente, o
    #   - ACK se pierde,
    # el sender puede retransmitir el MISMO frame protegido.
    # No se vuelve a ejecutar:
    #   - ASCON encryption en el sender,
    #   - policy selection,
    #   - signature generation,
    #   - checkpoint generation,
    #   - rekey.
    # Por tanto el retry representa principalmente overhead
    # acústico/link-layer.
    # Si la primera recepción válida ocurre durante un retry,
    # sí se contabiliza el procesamiento RX correspondiente.
    # ============================================================

    # ------------------------------------------------------------
    # Estadísticas del evento
    # ------------------------------------------------------------
    data_attempts = 1
    retransmissions = 0
    ack_attempts = 0
    ack_failures = 0
    ack_confirmed = False

    # ------------------------------------------------------------
    # Energía adicional causada por ACK/retries [J]
    # ------------------------------------------------------------
    ack_energy_j = 0.0
    retry_data_energy_j = 0.0

    # ------------------------------------------------------------
    # Procesamiento ocurrido específicamente durante retries [J]
    # Necesitamos separarlo para que posteriormente no aparezca
    # incorrectamente como energía de comunicación.
    # ------------------------------------------------------------
    retry_base_processing_energy_j = 0.0
    retry_ea_processing_energy_j = 0.0

    retry_base_processing_time_s = 0.0
    retry_ea_processing_time_s = 0.0
    retry_receiver_ops = {}

    # ------------------------------------------------------------
    # Latencia adicional causada por ACK/retry [s]
    # ------------------------------------------------------------
    link_extra_latency_s = 0.0

    # ------------------------------------------------------------
    # Standby adicional de los nodos NO participantes durante ARQ.
    # Este tiempo NO se suma a la latencia del hop porque ocurre
    # simultáneamente con ACK/retry.
    # Se usa únicamente para:
    #   - descontar energía standby de los demás nodos;
    #   - trazabilidad experimental.
    # ------------------------------------------------------------
    arq_standby_time_s = 0.0

    # ------------------------------------------------------------
    # Estado lógico del frame
    # accepted_once:
    #   el DATA ha sido aceptado al menos una vez.
    # crypto_rejected:
    #   el frame llegó físicamente pero falló su autenticación.
    # Un crypto reject NO debe resolverse retransmitiendo el mismo
    # ciphertext; por tanto no activamos ARQ en ese caso.
    # ------------------------------------------------------------
    accepted_once = bool(success)
    crypto_rejected = bool(
        channel_success
        and not success
    )

    # El receptor debe enviar ACK cuando acaba de aceptar DATA.
    ack_pending = bool(
        accepted_once
    )

    # ============================================================
    # ARQ loop
    # ============================================================
    while not crypto_rejected:
        # ========================================================
        # ACK correspondiente al último DATA recibido
        # ========================================================
        if ack_pending:
            ack_result = _simulate_minimal_ack(
                sender_node=sender_node,
                receiver_node=receiver_node,
                start_pos=start_pos,
                end_pos=end_pos,
                E_schedule=E_schedule,
                bitrate=bitrate,
                distance=distance,
                role_tx=role_tx,
                role_rx=role_rx,
                dest=dest,
                effective_per_override=
                    effective_per_override,
                verbose=VERBOSE,
            )

            ack_attempts += 1
            ack_energy_j += float(
                ack_result["energy_j"]
            )

            link_extra_latency_s += float(
                ack_result["latency_s"]
            )

            #####
            # El modelo TDMA reserva el slot hasta timeout.
            # La latencia real del ACK se mantiene separada en
            # ack_result["latency_s"].
            ack_standby_s = float(
                ack_result["timeout_s"]
            )

            if ack_standby_s > 0.0:
                nodes = update_energy_standby_others(
                    nodes,
                    active_ids,
                    active_cluster_id,
                    ack_standby_s,
                    verbose=VERBOSE,
                )

                arq_standby_time_s += (
                    ack_standby_s
                )
            #####

            ######
            # ========================================================
            # Log ACK TX / RX
            # ========================================================
            # Dirección ACK:
            #     DATA receiver -> DATA sender
            # Por tanto sender_id y receiver_id se invierten respecto
            # al DATA original.
            # Los ACK se registran como eventos físicos ARQ, pero NO
            # constituyen transacciones DAG independientes.
            # ========================================================
            ack_sender_id = receiver_id
            ack_receiver_id = sender_id

            ack_cluster_id = (
                receiver_node.get("ClusterHead")
                if dest != "Sink"
                else sender_node.get("ClusterHead")
            )

            ack_bits_received = (
                ACK_BITS
                if ack_result["success"]
                else 0
            )

            ack_residual_sender = (
                0.0
                if dest == "Sink"
                else float(
                    receiver_node.get(
                        "ResidualEnergy",
                        0.0
                    )
                )
            )

            ack_residual_receiver = float(
                sender_node.get(
                    "ResidualEnergy",
                    0.0
                )
            )

            # --------------------------------------------------------
            # ACK TX
            # --------------------------------------------------------
            log_event(
                run_id=RUN_ID,
                phase="data",
                module="arq",
                msg_type=(
                    f"ACK:{msg_type}:"
                    f"ATTEMPT{ack_attempts}:TX"
                ),
                sender_id=ack_sender_id,
                receiver_id=ack_receiver_id,
                cluster_id=ack_cluster_id,

                # Dirección inversa al DATA
                start_pos=end_pos,
                end_pos=start_pos,

                bits_sent=ACK_BITS,
                bits_received=ack_bits_received,

                # ACK no contiene payload de aplicación.
                payload_bits=0,
                success=bool(ack_result["success"]),
                packet_lost=not bool(ack_result["success"]),
                energy_event_type="tx",
                energy_j=float(ack_result["tx_energy_j"]),
                residual_sender=ack_residual_sender,
                residual_receiver=ack_residual_receiver,
                bitrate=bitrate,
                freq_khz=20,
                lat_prop_ms=float(ack_result["prop_ms"]),
                lat_tx_ms=float(ack_result["tx_ms"]),
                lat_proc_ms=0.0,
                snr_db=float(ack_result["snr_db"]),
                per=float(ack_result["per"]),
                lat_dag_ms=0.0,
                SL_db=float(ack_result["SL_db"]),
                EbN0_db=float(ack_result["EbN0_db"]),
                BER=float(ack_result["ber"]),
            )

            # --------------------------------------------------------
            # ACK RX
            # --------------------------------------------------------
            #
            # Si el ACK se pierde, este evento representa el consumo
            # de listening/timeout ya calculado por el helper.
            # --------------------------------------------------------

            log_event(
                run_id=RUN_ID,
                phase="data",
                module="arq",
                msg_type=(
                    f"ACK:{msg_type}:"
                    f"ATTEMPT{ack_attempts}:RX"
                ),
                sender_id=ack_sender_id,
                receiver_id=ack_receiver_id,
                cluster_id=ack_cluster_id,
                start_pos=end_pos,
                end_pos=start_pos,
                bits_sent=ACK_BITS,
                bits_received=ack_bits_received,
                payload_bits=0,
                success=bool(ack_result["success"]),
                packet_lost=not bool(ack_result["success"]),
                energy_event_type="rx",
                energy_j=float(ack_result["rx_energy_j"]),
                residual_sender=ack_residual_sender,
                residual_receiver=ack_residual_receiver,
                bitrate=bitrate,
                freq_khz=20,
                lat_prop_ms=float(ack_result["prop_ms"]),
                lat_tx_ms=float(ack_result["tx_ms"]),
                lat_proc_ms=0.0,
                snr_db=float(ack_result["snr_db"]),
                per=float(ack_result["per"]),
                lat_dag_ms=0.0,
                SL_db=float(ack_result["SL_db"]),
                EbN0_db=float(ack_result["EbN0_db"]),
                BER=float(ack_result["ber"]),
            )
            #######

            # ----------------------------------------------------
            # ACK recibido correctamente:
            # transacción link-layer finalizada.
            # ----------------------------------------------------
            if ack_result["success"]:
                ack_confirmed = True
                break


            # ----------------------------------------------------
            # ACK perdido:
            # el receiver puede haber recibido correctamente DATA,
            # pero el sender no tiene confirmación.
            # ----------------------------------------------------

            ack_failures += 1
            ack_pending = False


        # ========================================================
        # ¿Podemos retransmitir?
        # ========================================================
        if retransmissions >= MAX_DATA_RETRIES:
            break

        # ========================================================
        # DATA retry
        # ========================================================
        retransmissions += 1
        data_attempts += 1


        # --------------------------------------------------------
        # El sender retransmite exactamente el mismo frame.
        # NO:
        #   - vuelve a cifrar,
        #   - vuelve a firmar,
        #   - recalcula policy,
        #   - recalcula checkpoint.
        # Por tanto:
        #       t_verif_s = 0
        # --------------------------------------------------------

        (
            retry_prop_ms,
            retry_tx_ms,
            _,
            retry_timeout_s,
        ) = calculate_timeout(
            start_pos,
            end_pos,
            bitrate=bitrate,
            packet_size=bits_sent,
            proc_time_s=0.0,
        )

        # ========================================================
        # Sender DATA retry energy
        # ========================================================
        e0_retry_tx = float(
            sender_node["ResidualEnergy"]
        )

        sender_node = update_energy_node_tdma(
            sender_node,
            end_pos,
            E_schedule,
            retry_timeout_s,
            type_packet,
            role=role_tx,
            action="tx",
            verbose=VERBOSE,
            # Ciphertext ya existente.
            t_verif_s=0.0,
            packet_bits=bits_sent,
            bitrate=bitrate,
        )

        E_retry_tx = (
            e0_retry_tx
            - float(
                sender_node["ResidualEnergy"]
            )
        )

        # ========================================================
        # Channel result for retry DATA
        # ========================================================
        retry_channel_success = (
            propagate_with_probability(
                per=per_link,
                override_per=
                    effective_per_override,
            )
        )

        # ========================================================
        # Log DATA retry TX
        # ========================================================
        # El sender retransmite exactamente el mismo frame.
        # Por tanto:
        #   lat_proc_ms = 0
        # porque no repetimos:
        #   - Ascon ENC
        #   - policy selection
        #   - signature
        #   - checkpoint generation
        #   - rekey
        # ========================================================
        log_event(
            run_id=RUN_ID,
            phase="data",
            module="arq",
            msg_type=(
                f"DATA:{msg_type}:"
                f"RETRY{retransmissions}:TX"
            ),
            sender_id=sender_id,
            receiver_id=receiver_id,
            cluster_id=sender_node.get("ClusterHead"),
            start_pos=start_pos,
            end_pos=end_pos,
            bits_sent=bits_sent,
            bits_received=(
                bits_sent
                if retry_channel_success
                else 0
            ),
            payload_bits=application_payload_bits,

            # Aquí success representa entrega física del retry.
            success=bool(retry_channel_success),
            packet_lost=not bool(retry_channel_success),
            energy_event_type="tx",
            energy_j=float(E_retry_tx),
            residual_sender=sender_node["ResidualEnergy"],
            residual_receiver=(
                0
                if dest == "Sink"
                else receiver_node[
                    "ResidualEnergy"
                ]
            ),
            bitrate=bitrate,
            freq_khz=20,
            lat_prop_ms=float(retry_prop_ms),
            lat_tx_ms=float(retry_tx_ms),

            # El sender no vuelve a procesar crypto.
            lat_proc_ms=0.0,
            snr_db=snr_db,
            per=per_link,
            lat_dag_ms=0.0,
            SL_db=SL_db,
            EbN0_db=EbN0_db,
            BER=ber,
        )

        E_retry_rx = 0.0
        E_retry_ea_receiver = 0.0

        retry_rx_proc_s = 0.0
        retry_rx_ea_proc_s = 0.0

        # Duración real de este intento DATA retry.
        # Se determinará según éxito físico o timeout.
        retry_elapsed_s = 0.0

        # ========================================================
        # Retry DATA physically received
        # ========================================================
        if retry_channel_success:
            # ----------------------------------------------------
            # ¿DATA ya había sido aceptado antes?
            # Esto ocurre típicamente cuando:
            #   DATA success
            #   ACK lost
            #   DATA retransmitted
            # En ese caso asumimos duplicate detection y no
            # repetimos procesamiento criptográfico completo.
            # ----------------------------------------------------
            duplicate_delivery = bool(
                accepted_once
            )

            if not duplicate_delivery:
                # ------------------------------------------------
                # Esta es la PRIMERA recepción física válida del
                # frame.
                # El receiver debe ejecutar Ascon DEC.
                # ------------------------------------------------
                retry_rx_proc_s = t_dec_s

                retry_decrypted = decrypt_message(
                    shared_key,
                    encrypted_msg
                )

                retry_accepted = (
                    retry_decrypted is not None
                )

                # ------------------------------------------------
                # EA verification en la primera recepción válida
                # ------------------------------------------------
                retry_receiver_incremental = None
                if (
                    retry_accepted
                    and ea_enabled
                    and tx_ea is not None
                ):

                    retry_receiver_incremental = (
                        estimate_ea_incremental_processing(
                            policy,
                            side="receiver",
                            checkpoint_amortization=
                                checkpoint_factor,
                            checkpoint_input_bytes=256,
                            rekey_triggered=
                                rekey_triggered,
                            already_accounted_ops={
                                "ASCON_AEAD_DEC"
                            },
                        )
                    )

                    for op, count in (
                        retry_receiver_incremental[
                            "incremental_operation_counts"
                        ].items()
                    ):

                        retry_receiver_ops[op] = (
                            float(
                                retry_receiver_ops.get(
                                    op,
                                    0.0
                                )
                            )
                            + float(count)
                        )

                    retry_rx_ea_proc_s = (
                        float(
                            retry_receiver_incremental[
                                "incremental_processing_time_ms"
                            ]
                        )
                        / 1000.0
                    )
            else:
                # ------------------------------------------------
                # El frame es un duplicado ocasionado por ACK loss.
                # Modelo mínimo:
                # el receiver reconoce el frame ya aceptado y
                # simplemente vuelve a producir ACK.
                # ------------------------------------------------
                retry_accepted = True

            # ====================================================
            # Retry RX timing
            # ====================================================
            retry_receiver_total_proc_s = (
                retry_rx_proc_s
                + retry_rx_ea_proc_s
            )

            (
                _,
                _,
                _,
                retry_rx_timeout_s,
            ) = calculate_timeout(
                start_pos,
                end_pos,
                bitrate=bitrate,
                packet_size=bits_sent,
                proc_time_s=
                    retry_receiver_total_proc_s,
            )

            # ====================================================
            # Retry RX energy
            # ====================================================
            if dest != "Sink":
                e0_retry_rx = float(
                    receiver_node["ResidualEnergy"]
                )

                receiver_node = update_energy_node_tdma(
                    receiver_node,
                    start_pos,
                    E_schedule,
                    retry_rx_timeout_s,
                    type_packet,
                    role=role_rx,
                    action="rx",
                    verbose=VERBOSE,
                    # Ascon DEC únicamente cuando corresponde
                    # una primera recepción válida.
                    t_verif_s=
                        retry_rx_proc_s,

                    packet_bits=bits_sent,
                    bitrate=bitrate,
                )

                E_retry_rx = (
                    e0_retry_rx
                    - float(
                        receiver_node[
                            "ResidualEnergy"
                        ]
                    )
                )

                # ------------------------------------------------
                # EA receiver processing durante retry
                # ------------------------------------------------
                if (
                    not duplicate_delivery
                    and retry_accepted
                    and ea_enabled
                    and tx_ea is not None
                    and retry_receiver_incremental
                        is not None
                ):
                    retry_receiver_inc_mj = float(
                        retry_receiver_incremental[
                            "incremental_processing_energy_mj"
                        ]
                    )
                    E_retry_ea_receiver = (
                        apply_incremental_processing_energy(
                            receiver_node,
                            retry_receiver_inc_mj,
                        )
                    )

            # ====================================================
            # Processing-time bookkeeping
            # ====================================================
            # ASCON DEC se ejecuta siempre que esta sea la primera
            # recepción física del frame, incluso si finalmente falla
            # la autenticación.
            # EA verification, en cambio, solo se ejecuta cuando Ascon
            # aceptó previamente el frame.
            # ====================================================
            if not duplicate_delivery:
                # Ascon DEC/verify fue realmente ejecutado.
                retry_base_processing_time_s += (
                    retry_rx_proc_s
                )
                # Procesamiento EA solo si Ascon aceptó el frame.
                if retry_accepted:
                    retry_ea_processing_time_s += (
                        retry_rx_ea_proc_s
                    )

            # ====================================================
            # Processing-energy bookkeeping
            # ====================================================
            # La energía del Sink no forma parte del presupuesto
            # energético de los nodos sumergidos.
            # ====================================================
            if (
                not duplicate_delivery
                and dest != "Sink"
            ):
                # Ascon DEC fue ejecutado aunque el tag resulte inválido.
                retry_base_processing_energy_j += (
                    energy_proc_j(
                        retry_rx_proc_s
                    )
                )
                # EA processing solo ocurre después de una aceptación
                # Ascon válida.
                if retry_accepted:
                    retry_ea_processing_energy_j += (
                        E_retry_ea_receiver
                    )

            # ====================================================
            # Cryptographic reject during retry
            # ====================================================
            # Si el frame llegó físicamente pero Ascon lo rechazó,
            # retransmitir exactamente el mismo ciphertext no tiene
            # sentido.
            # Se detiene el ARQ para esta transacción.
            # ====================================================
            if (
                not duplicate_delivery
                and not retry_accepted
            ):
                crypto_rejected = True
                ack_pending = False
            
            # ====================================================
            # Retry accepted -> ACK becomes pending
            # ====================================================
            if retry_accepted:
                accepted_once = True
                ack_pending = True

            # ========================================================
            # Log DATA retry RX - frame physically received
            # ========================================================
            # Distinguimos:
            # retry_channel_success = True
            #       el frame llegó físicamente.
            # retry_accepted = True/False
            #       el frame fue o no aceptado criptográficamente.
            #
            # Por tanto packet_lost=False aunque un tag Ascon inválido
            # provoque retry_accepted=False.
            # ========================================================
            retry_rx_total_energy_j = (
                E_retry_rx
                + E_retry_ea_receiver
            )

            log_event(
                run_id=RUN_ID,
                phase="data",
                module="arq",
                msg_type=(
                    f"DATA:{msg_type}:"
                    f"RETRY{retransmissions}:RX"
                ),
                sender_id=sender_id,
                receiver_id=receiver_id,
                cluster_id=(
                    receiver_node.get("ClusterHead")
                    if dest != "Sink"
                    else sender_node.get("ClusterHead")
                ),
                start_pos=start_pos,
                end_pos=end_pos,
                bits_sent=bits_sent,
                # Solo entregamos bits útiles al protocolo si la
                # autenticación fue válida.
                bits_received=(
                    bits_sent
                    if retry_accepted
                    else 0
                ),
                payload_bits=application_payload_bits,
                # Resultado final de aceptación del retry.
                success=bool(
                    retry_accepted
                ),
                # El frame NO se perdió físicamente.
                packet_lost=False,
                energy_event_type="rx",
                energy_j=float(
                    retry_rx_total_energy_j
                ),
                residual_sender=
                    sender_node[
                        "ResidualEnergy"
                    ],
                residual_receiver=(
                    0
                    if dest == "Sink"
                    else receiver_node[
                        "ResidualEnergy"
                    ]
                ),
                bitrate=bitrate,
                freq_khz=20,
                lat_prop_ms=float(
                    retry_prop_ms
                ),
                lat_tx_ms=float(
                    retry_tx_ms
                ),
                lat_proc_ms=(
                    retry_receiver_total_proc_s
                    * 1000.0
                ),
                snr_db=snr_db,
                per=per_link,
                lat_dag_ms=0.0,
                SL_db=SL_db,
                EbN0_db=EbN0_db,
                BER=ber,
            )

            # ----------------------------------------------------
            # Duración del retry recibido correctamente.
            # Incluye:
            #   propagation
            #   + airtime
            #   + procesamiento RX realmente ejecutado
            # Todavía NO actualizamos link_extra_latency_s aquí.
            # Se hará una sola vez al final del intento.
            # ----------------------------------------------------
            retry_elapsed_s = (
                (
                    retry_prop_ms
                    + retry_tx_ms
                )
                / 1000.0
                + retry_receiver_total_proc_s
            )

        # ========================================================
        # Retry DATA lost
        # ========================================================
        else:
            if (
                dest != "Sink"
                and "ResidualEnergy"
                    in receiver_node
            ):

                e0_retry_failed_rx = float(
                    receiver_node[
                        "ResidualEnergy"
                    ]
                )

                receiver_node = (
                    update_energy_failed_rx(
                        receiver_node,
                        start_pos,
                        retry_timeout_s,
                        role=role_rx,
                        verbose=VERBOSE,
                    )
                )

                E_retry_rx = (
                    e0_retry_failed_rx
                    - float(
                        receiver_node[
                            "ResidualEnergy"
                        ]
                    )
                )

            # ========================================================
            # Log DATA retry RX - physical loss
            # ========================================================
            log_event(
                run_id=RUN_ID,
                phase="data",
                module="arq",
                msg_type=(
                    f"DATA:{msg_type}:"
                    f"RETRY{retransmissions}:RX"
                ),
                sender_id=sender_id,
                receiver_id=receiver_id,
                cluster_id=(
                    receiver_node.get("ClusterHead")
                    if dest != "Sink"
                    else sender_node.get("ClusterHead")
                ),
                start_pos=start_pos,
                end_pos=end_pos,
                bits_sent=bits_sent,
                bits_received=0,
                payload_bits=application_payload_bits,
                success=False,
                packet_lost=True,
                energy_event_type="rx",
                energy_j=float(
                    E_retry_rx
                ),
                residual_sender=
                    sender_node[
                        "ResidualEnergy"
                    ],
                residual_receiver=(
                    0
                    if dest == "Sink"
                    else receiver_node[
                        "ResidualEnergy"
                    ]
                ),
                bitrate=bitrate,
                freq_khz=20,
                lat_prop_ms=float(
                    retry_prop_ms
                ),
                lat_tx_ms=float(
                    retry_tx_ms
                ),
                lat_proc_ms=0.0,
                snr_db=snr_db,
                per=per_link,
                lat_dag_ms=0.0,
                SL_db=SL_db,
                EbN0_db=EbN0_db,
                BER=ber,
            )

            # ----------------------------------------------------
            # Retry físicamente perdido.
            #
            # El protocolo permanece ocupado hasta el timeout.
            # ----------------------------------------------------
            retry_elapsed_s = float(
                retry_timeout_s
            )


        # ========================================================
        # Retry elapsed time + standby accounting
        # ========================================================
        # Esta sección se ejecuta exactamente UNA vez por DATA retry,
        # independientemente de si el retry:
        #   - llegó y fue aceptado;
        #   - llegó y fue rechazado criptográficamente;
        #   - se perdió físicamente.
        # El mismo intervalo se usa para:
        #   1. latencia adicional ARQ;
        #   2. standby de los nodos no participantes.
        # ========================================================
        link_extra_latency_s += (
            retry_elapsed_s
        )

        # ========================================================
        # Standby durante el slot DATA retry
        # ========================================================
        # retry_elapsed_s:
        #     latencia real observada.
        # retry_timeout_s:
        #     duración reservada del slot TDMA y, por tanto,
        #     intervalo utilizado para energía standby.
        # ========================================================
        retry_standby_s = float(
            retry_timeout_s
        )

        if retry_standby_s > 0.0:
            nodes = update_energy_standby_others(
                nodes,
                active_ids,
                active_cluster_id,
                retry_standby_s,
                verbose=VERBOSE,
            )
            arq_standby_time_s += (
                retry_standby_s
            )
        #######

        # ========================================================
        # Total energy of this DATA retry
        # ========================================================
        retry_data_energy_j += (
            E_retry_tx
            + E_retry_rx
            + E_retry_ea_receiver
        )

    # ============================================================
    # Final logical DATA result
    # ============================================================
    success = bool(
        accepted_once
    )

    bits_rcv = (
        bits_sent
        if success
        else 0
    )

    ###
    # ============================================================
    # Retry statistics
    # ============================================================
    # Estos contadores serán posteriormente la fuente de Ret_i(t).
    # No calculamos todavía aquí el riesgo SR.
    # Solo almacenamos observaciones reales.
    # ============================================================
    if ea_ctx is not None:
        retry_stats = ea_ctx.setdefault(
            "_retry_stats",
            {}
        )

        node_retry_stats = (
            retry_stats.setdefault(
                int(sender_id),
                {
                    "logical_tx": 0,
                    "data_attempts": 0,
                    "retransmissions": 0,
                    "ack_attempts": 0,
                    "ack_failures": 0,
                }
            )
        )

        node_retry_stats[
            "logical_tx"
        ] += 1

        node_retry_stats[
            "data_attempts"
        ] += int(data_attempts)

        node_retry_stats[
            "retransmissions"
        ] += int(retransmissions)

        node_retry_stats[
            "ack_attempts"
        ] += int(ack_attempts)

        node_retry_stats[
            "ack_failures"
        ] += int(ack_failures)
    ###

    ####
    # ============================================================
    # Energy decomposition - common to Static and EA
    # ============================================================
    # Este bloque se ejecuta DESPUÉS del ARQ.
    # Por tanto integra:
    #   1. Primera transmisión DATA/AGG.
    #   2. Procesamiento criptográfico inicial.
    #   3. ACK(s).
    #   4. DATA retry/retries.
    #   5. Procesamiento RX ocurrido durante retries.
    #
    # La identidad que debe cumplirse es:
    #   E_total =
    #       E_communication
    #       + E_base_processing
    #       + E_EA_processing
    #
    # ============================================================

    # ============================================================
    # A) INITIAL DATA EVENT
    # ============================================================
    # E_tx y E_rx corresponden únicamente al PRIMER intento DATA.
    # IMPORTANTE:
    # E_tx / E_rx ya contienen el procesamiento base Ascon
    # contabilizado mediante update_energy_node_tdma().
    # ============================================================

    sender_base_event_energy_mj = (
        float(E_tx) * 1000.0
    )

    receiver_base_event_energy_mj = (
        float(E_rx) * 1000.0
    )

    # ------------------------------------------------------------
    # EA incremental energy actually accounted during INITIAL event
    # ------------------------------------------------------------
    ea_sender_incremental_mj = (
        float(E_ea_sender) * 1000.0
    )

    ea_receiver_incremental_mj = (
        float(E_ea_receiver) * 1000.0
    )

    initial_ea_incremental_energy_mj = (
        ea_sender_incremental_mj
        + ea_receiver_incremental_mj
    )

    # ============================================================
    # B) INITIAL BASE PROCESSING
    # ============================================================
    # Sender:
    #       Ascon ENC siempre se ejecuta una vez.
    # Receiver:
    #       Ascon DEC/verify únicamente si el primer frame llegó
    #       físicamente y se intentó descifrar.
    #
    # Para el Sink no incluimos energía en el presupuesto UWSN.
    # ============================================================
    base_sender_proc_mj = (
        energy_proc_j(t_enc_s)
        * 1000.0
    )

    if (
        rx_decrypt_attempted
        and dest != "Sink"
    ):

        base_receiver_proc_mj = (
            energy_proc_j(
                t_proc_rx_s
            )
            * 1000.0
        )
    else:
        base_receiver_proc_mj = 0.0

    initial_base_processing_energy_mj = (
        base_sender_proc_mj
        + base_receiver_proc_mj
    )

    # ============================================================
    # C) RETRY PROCESSING
    # ============================================================
    # Durante una retransmisión NO volvemos a ejecutar Ascon ENC
    # en el sender porque retransmitimos el mismo ciphertext.
    # Sin embargo, si el primer DATA se perdió y el retry llega por
    # primera vez al receiver, éste sí ejecuta:
    #       Ascon DEC
    #       + EA receiver processing
    # retry_*_processing_energy_j fue acumulado dentro del loop ARQ.
    # ============================================================
    retry_base_processing_energy_mj = (
        float(
            retry_base_processing_energy_j
        )
        * 1000.0
    )

    retry_ea_incremental_energy_mj = (
        float(
            retry_ea_processing_energy_j
        )
        * 1000.0
    )

    # ============================================================
    # D) TOTAL PROCESSING ENERGY
    # ============================================================
    base_processing_energy_mj = (
        initial_base_processing_energy_mj
        + retry_base_processing_energy_mj
    )

    ea_incremental_energy_mj = (
        initial_ea_incremental_energy_mj
        + retry_ea_incremental_energy_mj
    )

    total_processing_energy_mj = (
        base_processing_energy_mj
        + ea_incremental_energy_mj
    )

    # ============================================================
    # E) INITIAL COMMUNICATION ENERGY
    # ============================================================
    # El primer E_tx + E_rx incluye procesamiento base.
    # Lo eliminamos para obtener el componente estrictamente
    # asociado a comunicación/listening/timeout.
    # IMPORTANTE:
    # restamos SOLO el procesamiento del evento inicial.
    # ============================================================
    initial_communication_energy_mj = max(
        0.0,
        sender_base_event_energy_mj
        + receiver_base_event_energy_mj
        - initial_base_processing_energy_mj
    )

    # ============================================================
    # F) ACK + RETRY ENERGY
    # ============================================================
    # retry_data_energy_j contiene:
    #   DATA retry TX
    #   + retry RX/listening
    #   + EA receiver processing durante retry
    # ack_energy_j contiene:
     #   ACK TX
    #   + ACK RX/listening/timeout
    # ============================================================
    link_extra_energy_mj = (
        float(
            retry_data_energy_j
            + ack_energy_j
        )
        * 1000.0
    )

    # ------------------------------------------------------------
    # Parte computacional contenida dentro de retry_data_energy_j
    # ------------------------------------------------------------
    retry_processing_energy_mj = (
        retry_base_processing_energy_mj
        + retry_ea_incremental_energy_mj
    )

    # ------------------------------------------------------------
    # Comunicación adicional del ARQ
    # ------------------------------------------------------------
    retry_communication_energy_mj = max(
        0.0,

        link_extra_energy_mj
        - retry_processing_energy_mj
    )

    # ============================================================
    # G) TOTAL COMMUNICATION ENERGY
    # ============================================================
    communication_energy_mj = (
        initial_communication_energy_mj
        + retry_communication_energy_mj
    )

    # ============================================================
    # H) INITIAL TOTAL EVENT ENERGY
    # ============================================================
    # Estos valores describen únicamente el primer DATA.
    # No incluyen ACK ni retry.
    # ============================================================
    sender_total_event_energy_mj = (
        sender_base_event_energy_mj
        + ea_sender_incremental_mj
    )
    receiver_total_event_energy_mj = (
        receiver_base_event_energy_mj
        + ea_receiver_incremental_mj
    )

    initial_total_event_energy_mj = (
        sender_total_event_energy_mj
        + receiver_total_event_energy_mj
    )

    # ============================================================
    # I) FINAL ENERGY INCLUDING ARQ
    # ============================================================
    total_energy_mj = (
        initial_total_event_energy_mj
        + link_extra_energy_mj
    )
    ####

    ### 
    # ============================================================
    # 10) Log EA final
    #     Se ejecuta después de conocer:
    #       - TX/RX reales
    #       - PER/PDR
    #       - procesamiento incremental EA
    #       - latencia real
    # ============================================================

    if (
        ea_enabled
        and tx_ea is not None
        and ea_ctx.get("logger") is not None
    ):
        # --------------------------------------------------------
        # Estado observado.
        #
        # NOTA:
        # ea_state debe considerarse información LOCAL/LOGGING.
        # No debe interpretarse posteriormente como información
        # confiable transmitida por el nodo.
        # --------------------------------------------------------

        tx_ea.setdefault("ea_state", {})
        tx_ea["ea_state"]["initial_channel_success"] = bool(channel_success)
        tx_ea["ea_state"]["accepted"] = bool(success)
        tx_ea["ea_state"]["snr_db"] = snr_db
        tx_ea["ea_state"]["per_link"] = per_link
        tx_ea["ea_state"]["ber"] = ber
        tx_ea["ea_state"]["distance_m"] = distance
        tx_ea["ea_state"]["logical_delivery_success"] = bool(success)
        tx_ea["ea_state"]["ack_confirmed"] = bool(ack_confirmed)
        tx_ea["ea_state"]["retransmissions"] = int(retransmissions)

        # ========================================================
        # Store the energy decomposition already computed above
        # ========================================================
        #ea_cost.update #3 
        # ========================================================
        # FINAL ENERGY + ARQ ACCOUNTING
        # ========================================================
        #
        # Este bloque se ejecuta cuando ya conocemos:
        #
        #   - energía del primer DATA
        #   - energía RX inicial
        #   - ACK(s)
        #   - DATA retry/retries
        #   - procesamiento base durante retry
        #   - procesamiento EA durante retry
        #
        # Por tanto este es el lugar correcto para guardar
        # los contadores y costes finales del ARQ.
        # ========================================================

        ea_cost = tx_ea.setdefault(
            "ea_cost",
            {}
        )

        ea_cost.update({
            # ----------------------------------------------------
            # Initial DATA event
            # ----------------------------------------------------
            "sender_base_event_energy_mj":
                sender_base_event_energy_mj,
            "receiver_base_event_energy_mj":
                receiver_base_event_energy_mj,
            "sender_total_event_energy_mj":
                sender_total_event_energy_mj,
            "receiver_total_event_energy_mj":
                receiver_total_event_energy_mj,

            # ----------------------------------------------------
            # Processing
            # ----------------------------------------------------
            "base_processing_energy_mj":
                base_processing_energy_mj,
            "ea_sender_incremental_energy_mj":
                ea_sender_incremental_mj,
            "ea_receiver_incremental_energy_mj":
                ea_receiver_incremental_mj,
            "ea_incremental_energy_mj":
                ea_incremental_energy_mj,
            "processing_energy_mj":
                total_processing_energy_mj,

            # ----------------------------------------------------
            # Communication
            # ----------------------------------------------------
            "communication_energy_mj":
                communication_energy_mj,

            # ====================================================
            # MINIMAL ACK / ARQ
            # ====================================================
            # Total DATA attempts:
            #   1 = first transmission only
            #   2 = first transmission + one retry
            "data_attempts":
                int(data_attempts),

            # Number of actual DATA retransmissions.
            "retransmissions":
                int(retransmissions),

            # Number of ACK frames generated.
            "ack_attempts":
                int(ack_attempts),

            # Number of ACK frames lost.
            "ack_failures":
                int(ack_failures),

            # Sender received a final ACK.
            "ack_confirmed":
                bool(ack_confirmed),

            # Standby generated by ARQ
            "arq_standby_time_ms":
                float(
                    arq_standby_time_s
                    * 1000.0
                ),

            "other_nodes_arq_standby_accounted":
                True,

            # ----------------------------------------------------
            # ARQ energy decomposition
            # ----------------------------------------------------
            # DATA retransmissions only.
            "retry_data_energy_mj":
                float(
                    retry_data_energy_j
                    * 1000.0
                ),

            # ACK TX + RX/listening energy.
            "ack_energy_mj":
                float(
                    ack_energy_j
                    * 1000.0
                ),

            # Extra ARQ energy = retries + ACKs.
            "arq_overhead_energy_mj":
                float(
                    (
                        retry_data_energy_j
                        + ack_energy_j
                    )
                    * 1000.0
                ),

            # Mantener este campo por compatibilidad,
            # pero que represente SOLO DATA retransmitido.
            "retransmission_energy_mj":
                float(
                    retry_data_energy_j
                    * 1000.0
                ),

            # ----------------------------------------------------
            # Retry processing
            # ----------------------------------------------------
            "retry_base_processing_energy_mj":
                float(
                    retry_base_processing_energy_mj
                ),

            "retry_ea_processing_energy_mj":
                float(
                    retry_ea_incremental_energy_mj
                ),

            # ----------------------------------------------------
            # ARQ communication / processing decomposition
            # ----------------------------------------------------

            "initial_communication_energy_mj":
                float(
                    initial_communication_energy_mj
                ),

            "retry_communication_energy_mj":
                float(
                    retry_communication_energy_mj
                ),

            "link_extra_energy_mj":
                float(
                    link_extra_energy_mj
                ),

            "initial_total_event_energy_mj":
                float(
                    initial_total_event_energy_mj
                ),
            
            # ----------------------------------------------------
            # Final totals
            # ----------------------------------------------------
            "tx_energy_mj":
                sender_total_event_energy_mj,

            "rx_energy_mj":
                receiver_total_event_energy_mj,

            "total_energy_mj":
                total_energy_mj,

            "energy_scope":
                "ACTIVE_HOP_PLUS_ACK_ARQ",

            "network_standby_in_residual_energy":
                True,
        })
       
        ###
        # ========================================================
        # R1 PROCESSING-TIME DECOMPOSITION
        # ========================================================
        # IMPORTANTE:
        # Estos tiempos NO corresponden al tiempo wall-clock del
        # computador que ejecuta Python.
        # Los tiempos base:
        #       t_enc_s
        #       t_proc_rx_s
        # proceden de la calibración de Raspberry Pi 3 almacenada
        # en energia_dinamica.py.
        # Los tiempos EA:
        #       sender_ea_proc_s
        #       receiver_ea_proc_s
        #
        # proceden de los microbenchmarks EA realizados también
        # sobre Raspberry Pi 3.
        #
        # Por tanto, la simulación puede ejecutarse en otro PC sin
        # alterar los tiempos criptográficos modelados.
        # ========================================================
        # --------------------------------------------------------
        # Procesamiento criptográfico BASE U-Tangle.
        # Sender:
        #       ASCON encryption
        # Receiver:
        #       ASCON decryption/verification cuando el frame fue
        #       recibido físicamente, incluso si posteriormente
        #       falla la autenticación.
        # Para el Sink también podemos conservar el tiempo de
        # descifrado dentro de la latencia aunque su energía no se
        # cargue a la batería de la UWSN.
        # --------------------------------------------------------
        base_processing_time_ms = (
            t_enc_s

            + (
                t_proc_rx_s
                if rx_decrypt_attempted
                else 0.0
            )

            + retry_base_processing_time_s

        ) * 1000.0

        # --------------------------------------------------------
        # Procesamiento ADICIONAL introducido por EA-CryptoAgility.
        # Puede contener, dependiendo del perfil/evento:
        #       POLICY_MAC_GEN
        #       POLICY_MAC_VERIFY
        #       CHECKPOINT_HASH
        #       ED25519_SIGN
        #       ED25519_VERIFY
        #       X25519
        #       HKDF
        # ASCON no se vuelve a incluir porque pertenece al baseline.
        # --------------------------------------------------------
        ea_incremental_time_ms = (
            sender_ea_proc_s
            + receiver_ea_proc_s
            + retry_ea_processing_time_s
        ) * 1000.0

        # --------------------------------------------------------
        # Tiempo criptográfico/computacional total del evento.
        # --------------------------------------------------------
        total_processing_time_ms = (
            base_processing_time_ms
            + ea_incremental_time_ms
        )

        # --------------------------------------------------------
        # Guardar la descomposición para análisis posterior.
        # Esto nos permitirá generar directamente:
        #       baseline crypto time
        #       vs.
        #       EA incremental crypto time
        # sin reconstruir los valores desde otros campos del CSV.
        # --------------------------------------------------------

        # ea_cost.update #4
        ea_cost.update({
            "base_processing_time_ms":
                base_processing_time_ms,

            "ea_incremental_time_ms":
                ea_incremental_time_ms,

            "processing_time_ms":
                total_processing_time_ms,

            # Tiempo adicional introducido exclusivamente por
            # ACK / timeout / DATA retry.
            "arq_extra_latency_ms":
                float(link_extra_latency_s * 1000.0),

            # ----------------------------------------------------
            # Campo legado.
            # Se conserva temporalmente para que scripts antiguos
            # que esperan "crypto_time_ms" continúen funcionando.
            # Desde R1 su significado será:
            #       total cryptographic processing time
            # y NO únicamente Ascon.
            # ----------------------------------------------------
            "crypto_time_ms":
                total_processing_time_ms,

            
        })

        # ========================================================
        # FINAL END-TO-END HOP LATENCY
        # ========================================================
        # Primera transmisión:
        #   propagation
        #   + DATA airtime
        #   + Ascon ENC
        #   + EA sender processing
        #   + Ascon DEC
        #   + EA receiver processing
        # ARQ:
        #   + ACK airtime/propagation or timeout
        #   + DATA retransmission(s), if required
        #   + retry receiver processing, if required
        # link_extra_latency_s ya contiene todo el componente ARQ.
        # ========================================================
        total_latency_ms = (
            t_prop_s
            + t_tx_s
            + t_enc_s
            + sender_ea_proc_s
            + t_proc_rx_s
            + receiver_ea_proc_s
            + link_extra_latency_s
        ) * 1000.0

        ###
        sender_ops = (
            tx_ea.get("ea_cost", {}).get("sender_incremental_ops", {})
        )

        initial_receiver_ops = (
            tx_ea.get("ea_cost", {}).get(
                "receiver_incremental_ops",
                {}
            )
        )

        receiver_ops = dict(initial_receiver_ops)

        for op, count in (retry_receiver_ops.items()):
            receiver_ops[op] = (
                float(
                    receiver_ops.get(
                        op,
                        0.0
                    )
                )
                + float(count)
            )

        ea_cost["retry_receiver_ops"] = retry_receiver_ops

        all_ops = (
            set(sender_ops)
            | set(receiver_ops)
        )

        operation_counts = {
            op:
                float(sender_ops.get(op, 0.0))
                + float(receiver_ops.get(op, 0.0))

            for op in all_ops
        }

        ea_cost["operation_counts"] = (
            operation_counts
        )
        ###

        # ========================================================
        # Log EA final
        # ========================================================
        
        log_ea_transaction(
            logger=ea_ctx["logger"],
            run_id=ea_ctx["run_id"],
            seed=ea_ctx["seed"],
            scenario_id=ea_ctx["scenario_id"],
            tx=tx_ea,

            latency_ms=total_latency_ms,
            # accepted delivery
            pdr=(1.0 if success else 0.0 ),
            downgrade_injected=
                ea_ctx["scenario"].downgrade_detected,

            invalid_policy_meta=False,
            invalid_tx_rejected=False,
        )
    ######################
    
    # ============================================================
    # Optional energy-consistency diagnostic
    # ============================================================
    #
    # Funciona tanto para Static U-Tangle como para
    # EA-CryptoAgility porque utiliza exclusivamente variables
    # calculadas en el bloque energético común.
    # ============================================================

    if VERBOSE:

        reconstructed_total_mj = (
            communication_energy_mj
            + total_processing_energy_mj
        )

        energy_error_mj = (
            total_energy_mj
            - reconstructed_total_mj
        )

        print(
            "\n=== ENERGY CONSISTENCY ===",

            "\nE sender base [mJ] =",
            sender_base_event_energy_mj,

            "\nE sender total [mJ] =",
            sender_total_event_energy_mj,

            "\nE receiver base [mJ] =",
            receiver_base_event_energy_mj,

            "\nE receiver total [mJ] =",
            receiver_total_event_energy_mj,

            "\nE base processing [mJ] =",
            base_processing_energy_mj,

            "\nE EA incremental [mJ] =",
            ea_incremental_energy_mj,

            "\nE communication [mJ] =",
            communication_energy_mj,

            "\nE processing total [mJ] =",
            total_processing_energy_mj,

            "\nE total [mJ] =",
            total_energy_mj,

            "\nE communication + processing [mJ] =",
            reconstructed_total_mj,

            "\nNumerical error [mJ] =",
            energy_error_mj,
        )

    return encrypted_msg

import struct

def encode_marine_payload():
    # Rangos típicos
    temp = round(random.uniform(0.0, 30.0), 3)       # °C
    salinity = round(random.uniform(30.0, 40.0), 3)  # PSU
    pressure = round(random.uniform(0.0, 6000.0), 2) # dbar

    # Escalado
    T = int(temp * 1000)       # 3 decimales → uint16
    S = int(salinity * 1000)   # 3 decimales → uint16
    P = int(pressure * 10)     # 1 decimales → uint16 (hasta 6553.5 dbar)

    # Empaquetar en binario
    payload = struct.pack(">HHH", T, S, P)  # 6 bytes

    return payload, (temp, salinity, pressure)

