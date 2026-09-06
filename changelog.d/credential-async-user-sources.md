Credential service handlers now await provider operations without nested
Tokio runtimes, and Secret Service User scope is carried per authenticated
Credential request instead of the controller bootstrap. Guest credential
delivery accepts only injected Guest-local source ports and fails closed when
those endpoints are absent; test-only lease registries are no longer used by
production composition.
