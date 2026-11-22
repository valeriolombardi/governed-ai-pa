# PICEE-PA v1.3: Imputabilità Giuridica, Pattern di Interoperabilità ModI e Convalida della Decisione Algoritmica non-Esclusiva nella Pubblica Amministrazione

**Autore:** Valerio Lombardi  
**ORCID:** [0009-0006-3949-6228](https://orcid.org/0009-0006-3949-6228)  
**Data:** 22 Novembre 2026  
**Repository Ufficiale:** `https://github.com/valeriolombardi/governed-ai-pa`  
**Licenza:** CC-BY-4.0 (Documento) / Apache-2.0 (Software Engine)

---

## Abstract

L'introduzione di sistemi agentici basati su modelli computazionali nella Pubblica Amministrazione richiede un rigoroso inquadramento nell'ordinamento giuridico e amministrativo italiano ed europeo. Tale raccordo è governato da tre presidi normativi: (i) l'Articolo 14 del Regolamento (UE) 2024/1689 (*EU AI Act*), che richiede un'effettiva supervisione umana (*Human Oversight*) sui sistemi ad alto rischio; (ii) la giurisprudenza amministrativa del Consiglio di Stato (in particolare le Sentenze nn. 2270/2019, 8472/2019, 881/2020), che ammette l'utilizzo di algoritmi anche nell'attività discrezionale purché siano garantiti i principi di non-esclusività della decisione algoritmica, piena conoscibilità e trasparenza della logica computazionale, e imputabilità giuridica all'organo amministrativo competente; (iii) il Codice dell'Amministrazione Digitale (CAD, D.Lgs. 82/2005) e le Linee Guida AgID sull'Interoperabilità (ModI).

Questo technical paper presenta la specifica architetturale e il prototipo dimostrativo di **PICEE-PA v1.3**, introducendo il modulo **Administrative Imputation & Interoperability Gateway**. Il framework descrive un modello di controllo a stati finiti in cui le azioni automatizzate a rilevanza esterna o modificative (classi L2 e L3) sono vincolate alla validazione di una formale imputazione giuridica al funzionario/RUP competente, serializzando le evidenze crittografiche (catena di hash append-only e ledger digest) in buste applicative ispirate ai pattern di sicurezza ModI `INTEGRITY_REST_01`.

---

## 1. Il Quadro Giuridico: Dal Consiglio di Stato all'EU AI Act

### 1.1 Il Principio di Non-Esclusività della Decisione Algoritmica (Consiglio di Stato n. 8472/2019)
Nella sentenza 13 dicembre 2019, n. 8472, la Sezione VI del Consiglio di Stato ha affermato la legittimità dell'impiego di strumenti informatici e algoritmi anche nell'ambito di procedimenti connotati da discrezionalità amministrativa, subordinandola tuttavia a rigorosi limiti di garanzia. Tra questi emerge il **principio di non esclusività della decisione algoritmica**: il processo automatizzato non può esautorare la valutazione e la responsabilità del decisore umano, al quale compete verificare la coerenza dell'istruttoria ed esercitare il controllo effettivo sull'esito finale.

In PICEE-PA v1.3, questo principio si traduce nella seguente regola di garanzia applicata per classi di azione:
- Le azioni puramente assistive o di sintesi interna (**L0**) e le attività preparatorie prive di efficacia esterna (**L1**) non incidono su situazioni giuridiche terze e non necessitano di co-firma o imputazione formale.
- Le azioni a rilevanza esterna, vincolanti o a effetti patrimoniali/consequenziali (**L2** e **L3**) richiedono obbligatoriamente la presenza dell'`AdministrativeImputation` intestata al funzionario competente e l'esplicita negazione di decisionalità algoritmica esclusiva (`is_exclusive_algorithmic_decision = False`).
Se un agente tenta di inviare una transazione L2 o L3 dichiarandosi unico decisore autonomo, il motore `ConsiglioDiStatoValidator` scarta l'azione *fail-closed* sollevando l'eccezione `CdS_VIOLATION_8472`.

### 1.2 Piena Conoscibilità e Trasparenza della Regola (Consiglio di Stato n. 2270/2019)
La sentenza n. 2270/2019 ha statuito che la motivazione dell'atto amministrativo adottato con ausilio computazionale (Art. 3 L. 241/1990) deve consentire la piena verificabilità della regola applicata e dei parametri utilizzati.
In PICEE-PA, la Busta di Esecuzione Amministrativa (AEE) richiede obbligatoriamente:
- L'indicazione esplicita della base normativa di riferimento (`legal_framework`);
- L'impronta hash immutabile della specifica policy di autorizzazione (`policy.policy_hash`), mitigando il rischio di *Time-of-Check to Time-of-Use* (TOCTOU) e modifiche arbitrarie delle regole di calcolo a runtime.

### 1.3 Distinzione tra Identificazione Informatica, Firma Digitale e Validità Giuridica (CAD Artt. 20, 21 e 24)
Sul piano informatico-giuridico occorre distinguere:
1. **Autenticazione Informatica:** Sistemi quali SPID o CIE attestano l'identità dell'utente che accede a un servizio in rete.
2. **Firma Elettronica Qualificata / Digitale (Artt. 20 e 24 CAD):** Attesta la provenienza, l'integrità del documento e la volontà negoziale o provvedimentale del sottoscrittore con l'efficacia probatoria dell'art. 2702 c.c. L'apposizione della marca temporale qualificata (o validazione temporale elettronica) consente di renderne la collocazione temporale certa e opponibile ai terzi.
3. **Integrità Crittografica:** La catena sequenziale di hash SHA-256 (append-only ledger) garantisce matematicamente che le evidenze e i log non siano stati alterati post-esecuzione (*tamper-evidence*), ma non conferisce di per sé efficacia giuridica negoziale al documento in assenza di formale sottoscrizione.
4. **Validità Giuridica dell'Atto:** Presuppone la competenza dell'organo emanante, il rispetto delle forme procedimentali di legge (L. 241/1990) e la presenza della sottoscrizione digitale prescritta dal CAD.

---

## 2. Architettura del Framework PICEE-PA v1.3

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             AGENTE AUTONOMO PA                              │
│                      Proposta di Azione (AEE - Class L3)                    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 CONSIGLIO DI STATO COMPLIANCE VALIDATOR                     │
│  - Verifica Principio di Non-Esclusività (CdS 8472/2019)                    │
│  - Verifica Presenza Token Firma Digitale RUP (CAD Artt. 20, 24)            │
│  - Presidio Supervisione Umana Architetturale (EU AI Act Art. 14 design)    │
│  - Verifica Riferimento a Policy Immutabile (CdS 2270/2019)                 │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ [Esito: ALLOW]
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                 PICEE EVIDENCE CRYPTOGRAPHIC LEDGER                         │
│                 Generazione Fascicolo di Evidenza (AEB)                     │
│                 Append-Only Hash Chaining: sha256(H_i || H_prev)            │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              GATEWAY APPLICATIVO ISPIRATO A PATTERN AGID ModI               │
│  - Busta Dimostrativa: Pattern di Integrità INTEGRITY_REST_01               │
│  - Digest Imputazione Giuridica Responsabile del Procedimento                │
│  - Schema di Interoperabilità Applicativa Predisposto                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. La Busta Dimostrativa ispirata ai Pattern AgID ModI (`ModIInteropEnvelope`)

A titolo di prototipo applicativo per favorire l'interoperabilità dei sistemi nel settore pubblico, il payload post-esecuzione può essere incapsulato in una struttura dati che adotta convenzioni coerenti con le Linee Guida AgID ModI:

```json
{
  "message_id": "urn:modi:pa:c_xxxx:a1b2c3d4-e5f6-7890-abcd-ef0123456789",
  "issuer_ipa": "c_xxxx",
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
      "rup_name": "Mario Rossi",
      "rup_tax_code": "RSSMRA80A01H501U",
      "administrative_role": "Responsabile Unico del Progetto (RUP)",
      "is_exclusive_algorithmic_decision": false
    }
  }
}
```

> [!NOTE] Perimetro del Prototipo
> Tale envelope rappresenta una specifica applicativa aperta sviluppata come proof-of-concept. Non costituisce un'integrazione accreditata in ambiente nazionale PDND né una certificazione rilasciata da AgID.

---

## 4. Verifica dei Test Unitari del Prototipo

La correttezza logico-computazionale dei vincoli implementati è stata verificata mediante suite di unit test automatici (`tests/test_interop.py` e `tests/test_adversarial.py`):
- **Casi di test eseguiti:** 13 scenari di verifica algoritmica.
- **Esito dell'esecuzione:** 13/13 test superati.
- **Tempo di esecuzione:** ~0.003 secondi.
- **Scenari verificati:** Rilevazione e blocco di decisioni dichiarate esclusive, intercettazione di omissioni del token di firma digitale su atti L3, controllo dell'integrità crittografica della hash-chain e corretta serializzazione dei campi applicativi.

I risultati documentano il corretto funzionamento delle asserzioni software del codice di riferimento, non una validazione giuridica o conformità formale rilasciata da autorità di controllo.

---

## 5. Conclusioni

Il framework PICEE-PA v1.3 propone un modello concettuale e computazionale per tradurre i requisiti di non-esclusività, tracciabilità e imputabilità della L. 241/1990 e della giurisprudenza amministrativa in controlli software deterministici pre- e post-esecuzione. Ulteriori approfondimenti riguarderanno l'analisi dei costi di firma digitale per transazione e la compatibilità con i sistemi di protocollo e conservazione a norma.

---

### Citazione Bibliografica
```bibtex
@article{lombardi2026piceepa13,
  title={PICEE-PA v1.3: Imputabilit\`a Giuridica, Pattern di Interoperabilit\`a ModI e Convalida della Decisione Algoritmica non-Esclusiva nella Pubblica Amministrazione},
  author={Lombardi, Valerio},
  journal={Governed-AI-PA Technical Reports},
  year={2026},
  url={https://github.com/valeriolombardi/governed-ai-pa},
  note={ORCID: 0009-0006-3949-6228}
}
```
