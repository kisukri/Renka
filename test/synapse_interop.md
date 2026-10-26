# Running renka against a real Synapse

`TestSynapseInterop` (in `synapse_interop_test.go`) shares rooms with a real Synapse in both directions:
renka joins Synapse rooms (and backfills their history), Synapse joins renka rooms through an
invite, both servers exchange messages and state, a fork is resolved the same way on both sides,
end-to-end encryption keys, one-time keys, to-device messages and device list changes go both ways,
and the test compares the two servers' current state event by event. It is skipped unless `RENKA_SYNAPSE` is set.

1. Certificates (renka listens on 127.0.0.1:8449, Synapse federates on 127.0.0.1:8448):

   ```sh
   openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 30 -subj /CN=test-ca
   for n in synapse renka; do
     openssl req -newkey rsa:2048 -nodes -keyout $n.key -out $n.csr -subj /CN=127.0.0.1
     echo subjectAltName=IP:127.0.0.1 > $n.ext
     openssl x509 -req -in $n.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $n.crt -days 30 -extfile $n.ext
   done
   ```

2. Synapse (`pip install matrix-synapse`), generated with
   `python -m synapse.app.homeserver --server-name 127.0.0.1:8448 --config-path homeserver.yaml --generate-config --report-stats=no`,
   then in `homeserver.yaml`:

   ```yaml
   listeners:
     - {port: 8048, bind_addresses: ['127.0.0.1'], type: http, tls: false, resources: [{names: [client]}]}
     - {port: 8448, bind_addresses: ['127.0.0.1'], type: http, tls: true, resources: [{names: [federation]}]}
   tls_certificate_path: /path/synapse.crt
   tls_private_key_path: /path/synapse.key
   federation_custom_ca_list: [/path/ca.crt]
   ip_range_blacklist: []
   ip_range_whitelist: ['127.0.0.0/8']
   federation_ip_range_blacklist: []
   trusted_key_servers: []
   enable_registration: true
   enable_registration_without_verification: true
   ```

   plus generous `rc_*` rate limits.

3. Run:

   ```sh
   RENKA_SYNAPSE=http://127.0.0.1:8048 RENKA_SYNAPSE_NAME=127.0.0.1:8448 RENKA_TLS_DIR=/path \
     go test -run SynapseInterop -v ./internal/server
   ```
