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
- Client --> Python, Java
- Privacy Gateway Server --> C, Java, Swift 
- Ephemeral Worker Process --> C, Java, Swift 
- External Observer (Testing & Validation)

**Versions: [doing the project in several languages]**
- Python / C
- Python / Objective C
- Swift / Java

**Real Life Application 🐊**
- Client: devices have a cached dictionary to make sure the nodes are privacy preserving 
- DNS: Point to the correct global load balancer
- Global Load Balancer: point to the nearest and healthiest Ingress point 
- Ingress: Terminate TLS, Perform TCP, Attestation to the Client, Point to the nearest Gateway
- Gateway: Confirm auth
- PCC nodes : perform inference
- Special Additions: OHTTPS, HybridTLS

