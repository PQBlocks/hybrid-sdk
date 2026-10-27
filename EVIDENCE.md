# Evidence and Primary Sources

Every algorithm, combiner structure, and wire format implemented in `pqblocks-core` derives directly from formal standards and peer-reviewed specifications.

## Primary Sources and References

1. **NIST FIPS 203:**
   - *Title:* Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
   - *Publisher:* National Institute of Standards and Technology (NIST), August 2024
   - *Identifier:* [https://doi.org/10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)
   - *Usage:* Parameter set ML-KEM-768 for post-quantum key encapsulation.

2. **NIST FIPS 204:**
   - *Title:* Module-Lattice-Based Digital Signature Standard (ML-DSA)
   - *Publisher:* National Institute of Standards and Technology (NIST), August 2024
   - *Identifier:* [https://doi.org/10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)
   - *Usage:* Parameter set ML-DSA-65 for post-quantum digital signatures.

3. **RFC 7748:**
   - *Title:* Elliptic Curves for Security
   - *Authors:* A. Langley, M. Hamburg, S. Turner
   - *Publisher:* Internet Engineering Task Force (IETF), January 2016
   - *Identifier:* [https://doi.org/10.17487/RFC7748](https://doi.org/10.17487/RFC7748)
   - *Usage:* X25519 Diffie-Hellman key exchange for classical KEM component.

4. **RFC 8032:**
   - *Title:* Edwards-Curve Digital Signature Algorithm (Ed25519)
   - *Authors:* S. Josefsson, I. Liusvaara
   - *Publisher:* Internet Engineering Task Force (IETF), January 2017
   - *Identifier:* [https://doi.org/10.17487/RFC8032](https://doi.org/10.17487/RFC8032)
   - *Usage:* Pure Ed25519 for classical signature component.

5. **RFC 5869:**
   - *Title:* HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
   - *Authors:* H. Krawczyk, P. Eronen
   - *Publisher:* Internet Engineering Task Force (IETF), May 2010
   - *Identifier:* [https://doi.org/10.17487/RFC5869](https://doi.org/10.17487/RFC5869)
   - *Usage:* Secure combiner binding classical shared secret ($ss_{classical}$) and post-quantum shared secret ($ss_{pqc}$) with domain separation.

6. **draft-ietf-lamps-pq-composite-sigs-19:**
   - *Title:* Composite Signatures For Use In Internet PKI
   - *Authors:* M. Ounsworth, J. Gray, M. Pala, J. Klaußner
   - *Publisher:* IETF LAMPS Working Group, 2025
   - *Identifier:* [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)
   - *Usage:* Composite Ed25519 + ML-DSA-65 signature layout and dual verification logic.

## Method-to-Code Mapping

| Cryptographic Primitive | Standard / Specification | Source Implementation File | Automated Verification Test |
|---|---|---|---|
| **Hybrid KEM Keygen & Encaps** | FIPS 203 §6 / RFC 7748 §6.1 | `src/pqblocks_core/lib/libpqblocks_kem.so` | `tests/test_Adapter_LAYER_KEM_BINDING.py` |
| **Hybrid KEM Decaps & KDF** | RFC 5869 §2 (HKDF-SHA256) | `src/pqblocks_core/lib/libpqblocks_kem.so` | `tests/test_Golden Instance Test.py` |
| **Composite Signature Generation** | draft-ietf-lamps-pq-composite-sigs §3 | `src/pqblocks_core/lib/libpqblocks_sig.so` | `tests/test_Adapter Layer - SIG Binding.py` |
| **Composite Signature Verification** | draft-ietf-lamps-pq-composite-sigs §4 | `src/pqblocks_core/lib/libpqblocks_sig.so` | `tests/test_Misuse-Resistant Core - SIG.py` |
| **Error Taxonomy & String Translation** | Error Specification §7 | `src/pqblocks_core/lib/libpqblocks_errors.so` | `tests/test_error_taxonomy.py` |
| **Cryptographic Agility Policy** | Agility Specification §5 | `src/pqblocks_core/lib/libpqblocks_policy.so` | `tests/test_Policy Object & Versioning.py` |
| **CLI Dispatch Engine** | Command Specification §6, §12 | `src/pqblocks` | `tests/test_CLI Tool.py`, `tests/test_CLI Quickstart Verification.py` |
| **HSM Engine Delegation Pattern** | PKCS#11 Mechanism Delegation §11 | `src/pqblocks_core/pqblocks_hsm.h` | `tests/test_HSM Integration Points.py` |
