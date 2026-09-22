# PICEE-PA Minimal PoC v1.1

This PoC compares PICEE-PA with a deliberately stronger existing-technology baseline.

## Baseline
The baseline models a Cedar-like authorization request (principal, action, resource, context) and an OPA-like structured policy input. It applies the same semantic conditions as PICEE-PA and emits an ordinary audit event.

## PICEE-PA path
The PICEE-PA path represents the same authorization inputs as an Administrative Execution Envelope (AEE) and binds post-execution evidence to the AEE through hashes.

## Important interpretation
The PoC is not evidence that PICEE-PA makes a fundamentally new authorization decision. Both paths can make the same decisions. The testable differentiation is the portability and explicit structure of administrative execution context and evidence.

## Run

```bash
python -m unittest discover -s tests -v
python demo.py
```

No third-party Python dependencies are required.
