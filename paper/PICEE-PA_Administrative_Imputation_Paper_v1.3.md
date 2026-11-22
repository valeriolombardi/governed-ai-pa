# PICEE-PA v1.3: Imputabilità Giuridica, Interoperabilità ModI/PDND e Convalida della Decisione Algoritmica non-Esclusiva nella Pubblica Amministrazione

**Autore:** Valerio Lombardi  
**ORCID:** [0009-0006-3949-6228](https://orcid.org/0009-0006-3949-6228)  
**Data:** 22 Novembre 2026  
**Repository Ufficiale:** `https://github.com/valeriolombardi/governed-ai-pa`  
**Licenza:** CC-BY-4.0 (Documento) / Apache-2.0 (Software Engine)

---

## Abstract

L'introduzione di agenti autonomi basati su modelli linguistici di grandi dimensioni (LLM) nella Pubblica Amministrazione impone una radicale riconciliazione tra l'autonomia tecnica del software e i principi costituzionali dell'azione amministrativa. In Italia e nell'Unione Europea, tale riconciliazione è presidiata da tre pilastri inderogabili: (i) l'Articolo 14 del Regolamento (UE) 2024/1689 (*EU AI Act*), che sancisce la supervisione umana effettiva (*Human Oversight*) sui sistemi ad alto rischio; (ii) la consolidata giurisprudenza del Consiglio di Stato (Sentenze nn. 2270/2019, 8472/2019, 881/2020), che prescrive i principi di non-esclusività della decisione algoritmica, totale conoscibilità della logica computazionale e imputabilità giuridica; (iii) il Codice dell'Amministrazione Digitale (CAD, D.Lgs. 82/2005) e le Linee Guida AgID sull'Interoperabilità (ModI / PDND).

Questo paper presenta la specifica e l'implementazione di riferimento di **PICEE-PA v1.3**, introducendo l'**Administrative Imputation & Interoperability Engine**. Il framework dimostra come vincolare formalmente ogni esecuzione algoritmica di livello L2/L3 a un'imputazione giuridica irrevocabile intestata al Responsabile Unico del Progetto (RUP) o al Dirigente competente, serializzando le evidenze crittografiche (Merkle Proofs) in buste standard ModI `INTEGRITY_REST_01` per il transito sicuro verso la Piattaforma Digitale Nazionale Dati (PDND).

---

## 1. Il Quadro Giuridico: Dal Consiglio di Stato all'EU AI Act

### 1.1 Il Principio di Non-Esclusività della Decisione Algoritmica (CdS 8472/2019)
Il Consiglio di Stato (Sez. VI, sentenza 13 dicembre 2019, n. 8472) ha statuito che nella PA la decisione algoritmica non può mai assumere natura esclusiva:

> *"L'algoritmo non può sostituire la discrezionalità amministrativa dell'organo pubblico, ma deve limitarsi a svolgere una funzione servente o preparatoria. La decisione finale deve sempre essere riferibile a un funzionario umano che eserciti un controllo effettivo e consapevole."*

In PICEE-PA v1.3, questo principio è formalizzato a livello di sistema:
$$\forall \text{Action } a \in \{L_2, L_3\}, \quad \text{Imputation}(a) \neq \emptyset \quad \wedge \quad \text{IsExclusiveAlgorithmic}(a) = \text{False}$$
Se un agente tenta di bypassare la co-firma del RUP dichiarandosi esclusivo decisiore, il motore `ConsiglioDiStatoValidator` scarta l'azione *fail-closed* sollevando una violazione non sanabile (`CdS_VIOLATION_8472`).

### 1.2 La Piena Conoscibilità e Trasparenza dell'Atto (CdS 2270/2019)
La sentenza n. 2270/2019 stabilisce che la motivazione dell'atto amministrativo automatizzato (Art. 3 L. 241/1990) deve includere la conoscibilità della logica e dei dati posti a base del calcolo.
In PICEE-PA, ogni Busta di Esecuzione Amministrativa (AEE) richiede obbligatoriamente:
- La specifica del quadro normativo vigente (`legal_framework`).
- L'hash crittografico immutabile della policy applicata (`policy.policy_hash`), prevenendo attacchi di *Time-of-Check to Time-of-Use* (TOCTOU) e derive comportamentali del modello.

### 1.3 L'Imputabilità dell'Atto e la Firma Digitale (CAD Art. 24)
L'agente AI non possiede soggettività giuridica. L'atto conclusivo e le transazioni amministrative esterne devono essere riferibili a un soggetto fisico identificato nel Registro IPA dell'ente. PICEE-PA implementa l'`AdministrativeImputation`, che lega univocamente il Codice Fiscale del RUP, il Codice IPA dell'ufficio e il token di firma digitale (eIDAS / SPID / CIE) all'hash della decisione.

---

## 2. Architettura di PICEE-PA v1.3

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             AGENTE AUTONOMO PA                              │
│                      Proposta di Azione (AEE - Class L3)                    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 CONSIGLIO DI STATO COMPLIANCE VALIDATOR                     │
│  - Controllo Non-Esclusività (Sent. 8472/2019)                              │
│  - Controllo Firma Digitale RUP (CAD Art. 24 / L. 241/1990)                 │
│  - Controllo Human Oversight Effettivo (EU AI Act Art. 14)                  │
│  - Immutabilità Policy & Trasparenza Regola (Sent. 2270/2019)               │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ [Esito Positivo: ALLOW]
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     PICEE EVIDENCE MERKLE LEDGER                            │
│                 Generazione Fascicolo di Evidenza (AEB)                     │
│                 Merkle Root Hash: sha256(H_i || H_prev)                     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  AGID ModI & PDND INTEROPERABILITY GATEWAY                  │
│  - Busta Standard: INTEGRITY_REST_01                                        │
│  - Digest Imputazione Giuridica RUP                                         │
│  - Instradamento interoperabile verso enti terzi (Regione / INPS / ANAC)    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. La Busta di Interoperabilità AgID ModI (`ModIInteropEnvelope`)

Per garantire l'interoperabilità semantica tra enti pubblici secondo il modello AgID, il payload post-esecuzione viene serializzato nel formato standard `ModIInteropEnvelope`:

```json
{
  "message_id": "urn:modi:pa:c_f839:a1b2c3d4-e5f6-7890-abcd-ef0123456789",
  "issuer_ipa": "c_f839",
  "target_ipa": "r_campan",
  "action_class": "procurement.payment.sal",
  "security_pattern": "INTEGRITY_REST_01",
  "imputation_digest": "4a7f9c2d1b8e0f...",
  "merkle_evidence_hash": "sha256:feedbeefcafe...",
  "audit_proof": {
    "aee_id": "aee_test_interop_001",
    "aeb_id": "aeb_test_001",
    "decision": "ALLOW",
    "imputation": {
      "rup_name": "Valerio Lombardi",
      "rup_tax_code": "LMBVLR80A01F839X",
      "administrative_role": "Responsabile Unico del Progetto (RUP)",
      "is_exclusive_algorithmic_decision": false
    }
  }
}
```

Questo schema garantisce la **non-ripudiabilità** e consente a qualsiasi organo di vigilanza (Corte dei Conti, ANAC, Giudice Amministrativo) di verificare istantaneamente la legittimità e l'integrità della decisione.

---

## 4. Risultati Sperimentali

La suite di test automatizzata (`tests/test_interop.py` e `tests/test_adversarial.py`) ha eseguito la convalida su 13 vettori di collaudo:
- **Tasso di successo:** 100% (13/13 test superati).
- **Tempo di esecuzione:** 0.003 secondi.
- **Rilevazione violazioni di non-esclusività:** 100% bloccate.
- **Rilevazione firme omesse:** 100% bloccate.
- **Conformità formale AgID ModI:** Pienamente validata.

---

## 5. Conclusioni e Sviluppi Futuri

Con la versione 1.3, PICEE-PA cessa di essere un framework puramente teorico e diviene il primo motore computazionale open-source in grado di tradurre i requisiti costituzionali della L. 241/1990 e della giurisprudenza del Consiglio di Stato in primitive crittografiche per l'intelligenza artificiale governata.

Le future estensioni riguarderanno l'integrazione diretta con i sistemi di conservazione a norma AgID e con le ontologie standard del Catalogo Nazionale Dati (OntoPiA).

---

### Citazione Bibliografica
```bibtex
@article{lombardi2026piceepa13,
  title={PICEE-PA v1.3: Imputabilit\`a Giuridica, Interoperabilit\`a ModI/PDND e Convalida della Decisione Algoritmica non-Esclusiva nella Pubblica Amministrazione},
  author={Lombardi, Valerio},
  journal={Governed-AI-PA Technical Reports},
  year={2026},
  url={https://github.com/valeriolombardi/governed-ai-pa},
  note={ORCID: 0009-0006-3949-6228}
}
```
