# Ephemeral-Private-Inference-Gateway

- This project simulates private AI inference routing architecture where user requests are processed by ephemeral compute workers.
- The system is designed so that no user data persists beyond the lifetime of a single request not in logs, memory, or disk.
- The AI requests (the prompts) cannot ever be seen by any intermidiary network route (even the gateway itself).
- We handle HTTPS, and OHTTPS via a middle relay (to remove user identity).
- We perform attestion from the client to the node.

**What are we trying to mimic:**
- TGT, OTTS, REKs, DEKs for attestion and encryption
- x509 certificates for assymetric infrastructure and TLS
- Understanding of network protocols + security 
  
**Components:**
- Client --> Python
- Privacy Gateway Server --> C,  Swift 
- Ephemeral Worker Process --> C,  Swift 
- External Observer (Testing & Validation)


**Real Life Application 🐊**
- Client: devices have a cached dictionary to make sure the nodes are privacy preserving 
- DNS: Point to the correct global load balancer
- Global Load Balancer: point to the nearest and healthiest Ingress point 
- Ingress: Terminate TLS, Perform TCP, Attestation to the Client, Point to the nearest Gateway
- Gateway: Confirm auth
- PCC nodes : perform inference
- Special Additions: OHTTPS, HybridTLS

**Attestation Workflow**
````
[ Python Client ] ════════════ ( 1. Direct TLS Link ) ════════════► [ C Gateway Server ]
        │                                                                   │
        ◄─────────────── [ Sends Back Public REK Key ─────────────────────┘
````

**Inference routing workflow**

````

  [ Python Client ]
        │
        │  ( Encrypts prompt with Public REK )
        ▼
        │
        ├─── [ Connection 2: Unencrypted HTTP ] ───► [ Python Relay ]
        │     ( Payload is locked REK-garbage )               			│
        │                                                    		 		│ (Strips Client IP)
        │                                                     				▼
        │                                            					[ Python Relay ]
        │                                                    		 		│
        │                                                    		 		│
        ◄───────────────[ Connection 3: Brand New TLS Link ]┘
                                		( Terminates at Gateway )
                                      			│
                                      			▼
                               		[ C Gateway Server ]
                                      			│ ( Passes raw REK-garbage )
                                      			▼
                               [ C Worker / Node ]
                                ( Decrypts payload with Private REK )

````
