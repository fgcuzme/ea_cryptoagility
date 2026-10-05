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
#   DATA:
#       payload field = 60 B
#       header        = 10 B
#       total         = 70 B
#
#   AGG_DATA:
#       payload field = 92 B
#       header        = 11 B
#       total         = 103 B
#
# EA-CryptoAgility añade posteriormente policy metadata y
# cryptographic proofs sobre estos tamaños base.
# ============================================================
# PER_VARIABLE = None
VERBOSE = False
PAYLOAD_BITS_SN = 60*8 # 480 bits
PAYLOAD_BITS_CH = 92*8 # 736 bits

HEADER_BYTES_SN = 10
HEADER_BYTES_CH = 11

BASE_DATA_BYTES = 70
BASE_AGG_DATA_BYTES = 103

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
import os

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


import numpy as np
import random


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
    import random

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
    - ACK simulado al final del hop.
    """
    ## helper
    sender_node = _resolve_node_ref(nodes, sender_node, label="sender_node")
    receiver_node = _resolve_node_ref(nodes, receiver_node, label="receiver_node")

    # 0) Tipo de paquete por hop
    if source == 'SN' and dest == 'CH':
        msg_type = type_packet = 'data'
        role_tx, role_rx = 'SN', 'CH'
    elif source == 'CH' and dest == 'Sink':
        msg_type = type_packet = 'agg'
        role_tx, role_rx = 'CH', 'Sink'
    else:
        msg_type = type_packet = 'data'
        role_tx, role_rx = source, dest

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
    #
    # Las operaciones criptográficas se ejecutan realmente para
    # preservar la funcionalidad del protocolo.
    #
    # Sin embargo, el tiempo de procesamiento utilizado por el
    # simulador NO se mide con perf_counter() en el host Python.
    #
    # Los tiempos simulados provienen de la calibración realizada
    # sobre Raspberry Pi 3 y almacenada en energia_dinamica.py.
    # ============================================================

    encrypted_msg = encrypt_message(
        shared_key,
        plaintext
    )

    # desencrypted_msg = decrypt_message(
    #     shared_key,
    #     encrypted_msg
    # )

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
    #
    # La evaluación usa tamaños nominales fijos para el plano DATA.
    #
    # Esto evita que diferencias accidentales en la representación
    # Python del plaintext modifiquen la energía acústica o el PER.
    #
    # El objetivo experimental es que Static U-Tangle y
    # EA-CryptoAgility partan exactamente del mismo frame base.
    # ============================================================
    if source == "SN":
        # --------------------------------------------------------
        # Sensor Node -> Cluster Head
        #   protected payload field : 60 B
        #   protocol header         : 10 B
        #   baseline DATA frame     : 70 B
        # --------------------------------------------------------
        modeled_payload_bits = PAYLOAD_BITS_SN
        header_bytes = HEADER_BYTES_SN
        base_frame_bytes = BASE_DATA_BYTES
    else:
        # --------------------------------------------------------
        # Cluster Head -> Sink
        #   protected payload field : 92 B
        #   protocol header         : 11 B
        #   baseline AGG frame      : 103 B
        # --------------------------------------------------------
        modeled_payload_bits = PAYLOAD_BITS_CH
        header_bytes = HEADER_BYTES_CH
        base_frame_bytes = BASE_AGG_DATA_BYTES

    # ============================================================
    # Functional/model consistency check
    # ============================================================
    #
    # La simulación PHY utiliza tamaños nominales fijos de
    # U-Tangle (70 B / 103 B), mientras que encrypted_msg se
    # genera realmente para comprobar la funcionalidad Ascon.
    #
    # Debemos garantizar que la representación criptográfica real
    # nunca exceda el campo reservado por el modelo.
    # ============================================================

    functional_ciphertext_bytes = len(encrypted_msg)

    modeled_protected_field_bytes = (
        modeled_payload_bits // 8
    )

    if (
        functional_ciphertext_bytes
        > modeled_protected_field_bytes
    ):
        raise ValueError(
            "Functional Ascon representation exceeds "
            "the modeled protected field: "
            f"{functional_ciphertext_bytes} B > "
            f"{modeled_protected_field_bytes} B"
        )

    # ------------------------------------------------------------
    # Baseline frame actually used by the acoustic model.
    # ------------------------------------------------------------
    normal_bits_sent = (
        modeled_payload_bits
        + header_bytes * 8
    )

    # ------------------------------------------------------------
    # Consistency check.
    #
    # Detecta inmediatamente una modificación accidental de las
    # constantes que rompa la configuración del baseline.
    # ------------------------------------------------------------
    assert normal_bits_sent == base_frame_bytes * 8, (
        "Inconsistent U-Tangle baseline packet size: "
        f"computed={normal_bits_sent / 8:.0f} B, "
        f"expected={base_frame_bytes} B"
    )

    # ------------------------------------------------------------
    # Sin EA, este es el tamaño final.
    #
    # Si EA está activo, policy_meta/proofs se añadirán después.
    # ------------------------------------------------------------
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

        # tx_ea = {
        #     "ID": f"DATA-{sender_id}-{receiver_id}-{time.time()}",
        #     "Source": sender_id,
        #     "Type": "DATA" if source == "SN" else "AGG",
        #     "message_type": message_type_ea,
        #     "Payload": plaintext if isinstance(plaintext, str) else str(plaintext),
        #     "ApprovedTx": [],
        # }

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

        policy_meta_bytes = int(ea_cost.get("policy_meta_bytes", 0))
        # crypto_proof_bytes = int(ea_cost.get("crypto_proof_bytes", 0))

        # checkpoint_rule = tx_ea.get("Policy", {}).get("checkpoint_rule", "")

        # profile_id = tx_ea.get("Policy", {}).get("profile_id", "")
        # checkpoint_rule = tx_ea.get("Policy", {}).get("checkpoint_rule", "")

        # K_PERIODIC = int(os.environ.get("EA_CHECKPOINT_K_PERIODIC", "10"))
        # K_BATCHED = int(os.environ.get("EA_CHECKPOINT_K_BATCHED", "25"))
        # K_DELAYED = int(os.environ.get("EA_CHECKPOINT_K_DELAYED", "30"))

  
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

        policy_meta_bytes = int(
            POLICY_META_SIZE_BYTES
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

        ea_cost.update({
            "policy_meta_bytes":
                policy_meta_bytes,

            "crypto_proof_bytes":
                extra_proof_bytes,

            "ea_overhead_bits":
                ea_overhead_bits,

            "normal_bits_sent":
                normal_bits_sent,

            "effective_bits_sent":
                bits_sent,

            "tx_size_bytes":
                int(
                    math.ceil(
                        bits_sent / 8.0
                    )
                ),

            # Periodicidad configurada.
            "checkpoint_k":
                checkpoint_k,

            # Indica si ESTA transacción contiene checkpoint.
            "checkpoint_due":
                checkpoint_due,

            # Compatibilidad temporal con análisis anteriores.
            "checkpoint_amortization_k":
                checkpoint_k,

            # El campo legacy ya no significa 1/K.
            # Ahora vale exclusivamente 0.0 o 1.0.
            "checkpoint_amortization":
                checkpoint_factor,

            "rekey_triggered":
                rekey_triggered,

            "ea_sender_incremental_time_ms":
                sender_incremental[
                    "incremental_processing_time_ms"
                ],

            "ea_sender_incremental_energy_mj":
                sender_incremental[
                    "incremental_processing_energy_mj"
                ],

            "sender_incremental_ops":
                sender_incremental[
                    "incremental_operation_counts"
                ],

            "functional_ciphertext_bytes":
                functional_ciphertext_bytes,

            "modeled_protected_field_bytes":
                modeled_protected_field_bytes,

            "modeled_slack_bytes":
                (
                    modeled_protected_field_bytes
                    - functional_ciphertext_bytes
                ),

            "modeled_baseline_frame_bytes":
                base_frame_bytes,
        })
        ####

        # ea_overhead_bits = 8 * (policy_meta_bytes + crypto_proof_bytes)

        # # Tamaño físico efectivo bajo EA:
        # # ciphertext real + header normal + metadata/proof EA.
        # bits_sent = normal_bits_sent + ea_overhead_bits

        # Guardar trazabilidad para el CSV EA.
        # ea_cost["ciphertext_bytes"] = len(encrypted_msg)
        ea_cost["functional_ciphertext_bytes"] = len(encrypted_msg)
        ea_cost["modeled_baseline_frame_bytes"] = base_frame_bytes
        ea_cost["modeled_payload_bytes"] = modeled_payload_bits // 8
        ea_cost["header_bytes"] = header_bytes
        # ea_cost["normal_bits_sent"] = normal_bits_sent
        # ea_cost["ea_overhead_bits"] = ea_overhead_bits
        # ea_cost["effective_bits_sent"] = bits_sent
        # ea_cost["tx_size_bytes"] = int((bits_sent + 7) // 8)

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
    #
    # channel_success indica exclusivamente que el frame acústico
    # llegó al receptor.
    #
    # No implica todavía que el frame sea criptográficamente
    # válido.
    # ============================================================

    channel_success = propagate_with_probability(
        per=per_link,
        override_per=effective_per_override,
    )

    # Resultado final de aceptación del paquete.
    success = channel_success

    p_lost = not channel_success

    bits_rcv = (
        bits_sent
        if channel_success
        else 0
    )

    if channel_success:
        # El receptor realmente recibió el frame y por tanto
        # intenta la verificación AEAD.
        rx_decrypt_attempted = True

        t_proc_rx_s = t_dec_s

        decrypted_msg = decrypt_message(
            shared_key,
            encrypted_msg
        )

        if decrypted_msg is None:

            # El frame llegó físicamente, pero no fue aceptado
            # criptográficamente.
            success = False
            bits_rcv = 0

    # Permite distinguir energía de una operación criptográfica
    # intentada aunque posteriormente falle la autenticación.
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
    if ea_enabled and tx_ea is not None:

        sender_inc_mj = float(
            tx_ea["ea_cost"].get(
                "ea_sender_incremental_energy_mj",
                0.0
            )
        )

        E_ea_sender = \
            apply_incremental_processing_energy(
                sender_node,
                sender_inc_mj
            )

        E_tx_total = (
            E_tx
            + E_ea_sender
        )
    ###

    # 7) Log TX (emisor)
    log_event(
        run_id=RUN_ID, phase="data", module="ascon", msg_type=f"DATA:{msg_type}:TX",
        sender_id=sender_id, receiver_id=receiver_id, cluster_id=sender_node.get("ClusterHead"),
        start_pos=start_pos, end_pos=end_pos,
        bits_sent=bits_sent, bits_received=bits_rcv, payload_bits=modeled_payload_bits,
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


    ## Se actualiza el 8 y 9
    # ============================================================
    # 8) Si el paquete llega: energía RX + descifrado + EA policy
    # ============================================================

    # Valores por defecto para evitar variables no inicializadas
    E_rx = 0.0                  # J: evento RX base U-Tangle
    E_ea_receiver = 0.0         # J: procesamiento incremental EA
    t_proc_rx_s = 0.0           # s: descifrado base
    receiver_ea_proc_s = 0.0    # s: procesamiento adicional EA
    receiver_incremental = None
    decrypted_msg = None

    if success:
        # --------------------------------------------------------
        # Procesamiento base del receptor: ASCON decrypt
        # --------------------------------------------------------
        t_proc_rx_s = t_dec_s
        decrypted_msg = decrypt_message(
            shared_key,
            encrypted_msg
        )

        if decrypted_msg is None:
            success = False
            p_lost = True
            bits_rcv = 0

        # --------------------------------------------------------
        # Procesamiento adicional EA-CryptoAgility
        #
        # IMPORTANTE:
        # ASCON_AEAD_DEC se excluye porque ya será contabilizado
        # por update_energy_node_tdma(..., t_verif_s=t_dec_s).
        # --------------------------------------------------------
        if (
            ea_enabled
            and tx_ea is not None
            # and dest != "Sink"
        ):

            receiver_incremental = (
                estimate_ea_incremental_processing(
                    policy,
                    side="receiver",
                    # Mismo evento checkpoint que transportó el sender.
                    # Sender y receiver deben procesar exactamente
                    # el mismo checkpoint.
                    checkpoint_amortization=
                        checkpoint_factor,
                    # Provisional hasta verificar el objeto real
                    # que se usa como checkpoint.
                    checkpoint_input_bytes=256,
                    rekey_triggered=
                        rekey_triggered,
                    already_accounted_ops={
                        "ASCON_AEAD_DEC"
                    },
                )
            )

            receiver_ea_proc_s = (
                float(
                    receiver_incremental[
                        "incremental_processing_time_ms"
                    ]
                )
                / 1000.0
            )

        # --------------------------------------------------------
        # Tiempo total de procesamiento observado en RX
        #
        # Esto afecta a la LATENCIA.
        #
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
            #
            # Aquí se contabiliza:
            #   - RX acústico
            #   - tiempo/passive/listen según el modelo
            #   - ASCON decrypt mediante t_verif_s=t_dec_s
            #
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
            if receiver_incremental is not None:
                receiver_inc_mj = float(
                    receiver_incremental[
                        "incremental_processing_energy_mj"
                    ]
                )
                # Devuelve J realmente descontados
                E_ea_receiver = (
                    apply_incremental_processing_energy(
                        receiver_node,
                        receiver_inc_mj,
                    )
                )
                # ------------------------------------------------
                # Guardar descomposición EA
                # ------------------------------------------------

                if tx_ea is not None:
                    ea_cost = tx_ea.setdefault(
                        "ea_cost",
                        {}
                    )
                    ea_cost.update({
                        "ea_receiver_incremental_time_ms":
                            receiver_incremental[
                                "incremental_processing_time_ms"
                            ],
                        "ea_receiver_incremental_energy_mj":
                            E_ea_receiver * 1000.0,
                        "receiver_incremental_ops":
                            receiver_incremental[
                                "incremental_operation_counts"
                            ],
                    })

        # --------------------------------------------------------
        # Sink:
        # actualmente no se modela consumo RX del Sink
        # --------------------------------------------------------
        else:
            E_rx = 0.0
            E_ea_receiver = 0.0

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
            payload_bits=modeled_payload_bits,
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
                payload_bits=modeled_payload_bits,
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

        else:
            E_rx = 0.0

        E_rx_total = E_rx
    ##################################

    ####
    # ============================================================
    # Energy decomposition - common to Static and EA
    # ============================================================
    sender_base_event_energy_mj = (
        float(E_tx) * 1000.0
    )

    receiver_base_event_energy_mj = (
        float(E_rx) * 1000.0
    )

    ea_sender_incremental_mj = (
        float(E_ea_sender) * 1000.0
    )

    ea_receiver_incremental_mj = (
        float(E_ea_receiver) * 1000.0
    )

    ea_incremental_energy_mj = (
        ea_sender_incremental_mj
        + ea_receiver_incremental_mj
    )

    # Base cryptographic processing already included in E_tx/E_rx
    base_sender_proc_mj = (
        energy_proc_j(t_enc_s)
        * 1000.0
    )

    if (
        rx_decrypt_attempted
        and dest != "Sink"
    ):
        base_receiver_proc_mj = (
            energy_proc_j(t_proc_rx_s)
            * 1000.0
        )
    else:
        base_receiver_proc_mj = 0.0

    base_processing_energy_mj = (
        base_sender_proc_mj
        + base_receiver_proc_mj
    )

    # Non-computational component
    communication_energy_mj = max(
        0.0,
        sender_base_event_energy_mj
        + receiver_base_event_energy_mj
        - base_processing_energy_mj
    )

    # Total processing
    total_processing_energy_mj = (
        base_processing_energy_mj
        + ea_incremental_energy_mj
    )

    # Actual sender/receiver event energy
    sender_total_event_energy_mj = (
        sender_base_event_energy_mj
        + ea_sender_incremental_mj
    )

    receiver_total_event_energy_mj = (
        receiver_base_event_energy_mj
        + ea_receiver_incremental_mj
    )

    total_energy_mj = (
        sender_total_event_energy_mj
        + receiver_total_event_energy_mj
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
        tx_ea["ea_state"]["snr_db"] = snr_db
        tx_ea["ea_state"]["per_link"] = per_link
        tx_ea["ea_state"]["ber"] = ber
        tx_ea["ea_state"]["distance_m"] = distance

        # ========================================================
        # Store the energy decomposition already computed above
        # ========================================================
        ea_cost = tx_ea.setdefault(
            "ea_cost",
            {}
        )

        ea_cost.update({
            # ----------------------------------------------------
            # Base U-Tangle event energy
            # ----------------------------------------------------
            "sender_base_event_energy_mj":
                sender_base_event_energy_mj,
            "receiver_base_event_energy_mj":
                receiver_base_event_energy_mj,

            # ----------------------------------------------------
            # Complete sender/receiver event energy
            # including EA incremental processing
            # ----------------------------------------------------
            "sender_total_event_energy_mj":
                sender_total_event_energy_mj,
            "receiver_total_event_energy_mj":
                receiver_total_event_energy_mj,

            # ----------------------------------------------------
            # Compatibility fields
            # ----------------------------------------------------
            "tx_energy_mj":
                sender_total_event_energy_mj,
            "rx_energy_mj":
                receiver_total_event_energy_mj,

            # ----------------------------------------------------
            # Processing decomposition
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
            # Acoustic / non-processing component
            # ----------------------------------------------------
            "communication_energy_mj":
                communication_energy_mj,

            # ----------------------------------------------------
            # Total event energy
            # ----------------------------------------------------
            "total_energy_mj":
                total_energy_mj,
            "energy_scope":
                "MEASURED_EVENT_PLUS_EA_INCREMENTAL",
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
        #       ASCON decryption únicamente si el paquete fue
        #       recibido correctamente.
        # Para el Sink también podemos conservar el tiempo de
        # descifrado dentro de la latencia aunque su energía no se
        # cargue a la batería de la UWSN.
        # --------------------------------------------------------
        base_processing_time_ms = (
            t_enc_s
            + (
                t_proc_rx_s
                if success
                else 0.0
            )
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
            + (
                receiver_ea_proc_s
                if success
                else 0.0
            )
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
        ea_cost.update({
            "base_processing_time_ms":
                base_processing_time_ms,

            "ea_incremental_time_ms":
                ea_incremental_time_ms,

            "processing_time_ms":
                total_processing_time_ms,

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
        # LATENCY R1
        # ========================================================

        # Sender:
        #   ASCON ENC + procesamiento EA
        #
        # Receiver:
        #   ASCON DEC + procesamiento EA
        #
        # Si el paquete se pierde:
        #   receiver_ea_proc_s = 0
        #   t_proc_rx_s = 0
        # ========================================================

        total_latency_ms = (
            t_prop_s
            + t_tx_s
            + t_enc_s
            + sender_ea_proc_s
            + t_proc_rx_s
            + receiver_ea_proc_s
        ) * 1000.0

        ###
        sender_ops = (
            tx_ea.get(
                "ea_cost", {}
            ).get(
                "sender_incremental_ops",
                {}
            )
        )

        receiver_ops = (
            tx_ea.get(
                "ea_cost", {}
            ).get(
                "receiver_incremental_ops",
                {}
            )
            if success
            else {}
        )

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

            pdr=(
                1.0
                if success
                else 0.0
            ),
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

