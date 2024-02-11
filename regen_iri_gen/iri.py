import base64
from enum import IntEnum
import hashlib

import base58
from pyld import jsonld

from .content_hash import (
    ContentHash,
    ContentHashGraph,
    DigestAlgorithm,
    GraphCanonicalizationAlgorithm,
    GraphMerkleTree,
)


class IriVersion(IntEnum):
    Version0 = 0


class IriPrefix(IntEnum):
    Raw = 0
    Graph = 1


def to_iri(content_hash: ContentHash):
    content_hash_graph = content_hash.graph
    if content_hash_graph is None:
        raise ValueError("Only graph content hash is supported.")

    # Start byte array.
    bytes_array = bytearray(5)
    bytes_array[0] = IriVersion.Version0
    bytes_array[1] = IriPrefix.Graph
    bytes_array[2] = content_hash_graph.canonicalization_algorithm
    bytes_array[3] = content_hash_graph.merkle_tree
    bytes_array[4] = content_hash_graph.digest_algorithm

    # Decode the base64 encoded string from the content hash.
    hash_bytes = base64.b64decode(content_hash_graph.hash.encode())

    # Append hash bytes to bytes array.
    hash_string = base58.b58encode_check(bytes_array + hash_bytes)

    # Return decoded string.
    decoded = hash_string.decode("UTF-8")
    return f"regen:{decoded}.rdf"


def parse_iri(iri: str) -> ContentHash:
    # Get the regen: prefix.
    prefix = iri[:6]
    if prefix != "regen:":
        raise ValueError("Invalid IRI prefix.")

    # Get the hash and extension.
    iri_parts = iri[6:].split(".")
    if len(iri_parts) < 2:
        raise ValueError("Invalid IRI extension.")

    # Unpack parts.
    hash_str, extension = iri_parts
    if extension != "rdf":
        raise ValueError("Only graph content hash is supported.")

    # Decode the hash to bytes.
    try:
        hash_bytes = base58.b58decode_check(hash_str)
    except Exception:
        raise ValueError("Invalid IRI hash.")

    # Ensure the hash bytes are correct.
    if len(hash_bytes) < 6:
        raise ValueError("Invalid IRI data.")
    if hash_bytes[0] != IriVersion.Version0:
        raise ValueError("Invalid IRI version.")

    # Only support graph content hash.
    if hash_bytes[1] != IriPrefix.Graph:
        raise ValueError("Only graph content hash is supported.")

    # Build content hash
    content_hash_graph = ContentHashGraph(
        canonicalization_algorithm=hash_bytes[2],
        merkle_tree=hash_bytes[3],
        digest_algorithm=hash_bytes[4],
        hash=hash_bytes[5:],
    )
    return ContentHash(graph=content_hash_graph)


def document_to_iri(document):
    # Canonicalization.
    normalized = jsonld.normalize(
        document, {"format": "application/n-quads", "algorithm": "URDNA2015"}
    )

    # Hash.
    binary = normalized.encode("utf-8")
    digest = hashlib.blake2b(binary, digest_size=32).digest()

    # Build content hash and generate IRI.
    content_hash_graph = ContentHashGraph(
        hash=digest,
        digest_algorithm=DigestAlgorithm.BLAKE2B_256,
        canonicalization_algorithm=GraphCanonicalizationAlgorithm.URDNA2015,
        merkle_tree=GraphMerkleTree.NONE_UNSPECIFIED,
    )
    content_hash = ContentHash(graph=content_hash_graph)
    return to_iri(content_hash)
