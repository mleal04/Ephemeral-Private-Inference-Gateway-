# Ephemeral-Private-Inference-Gateway

- This project simulates a privacy-preserving AI inference infrastructure where user requests are processed by ephemeral compute workers.
- The system is designed so that no user data persists beyond the lifetime of a single request not in logs, memory, or disk.
- The goal is to enforce privacy by system design, not by policy.

**Goals:**
- Ensure no request data is stored
- Enforce ephemeral computation
- Demonstrate clear trust boundaries
- Simulate AI inference request handling at infrastructure level
  
**Components:**
- Client --> Python
- Privacy Gateway Server --> C, Swift 
- Ephemeral Worker Process --> C, Swift 
- External Observer (Testing & Validation)

**Versions: [doing the project in several languages]**
- Python / C
- Python / Swift

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


