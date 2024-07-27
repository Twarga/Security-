# Summary: Security Architecture

**1. Cloud:**
- **Responsibility Matrix:** Defines security roles between provider and customer; clarifies responsibilities.
- **Hybrid Considerations:** Ensures consistent security across private and public clouds.
- **Third-party Vendors:** Leverages external security but requires due diligence.

**2. Infrastructure as Code (IaC):** Automates deployment, ensuring consistent security configurations and reducing errors.

**3. Serverless:** Eliminates server management, reducing the attack surface but requiring secure function permissions and API gateways.

**4. Microservices:** Breaks applications into isolated services for better scalability and security.

**5. Network Infrastructure:**
- **Physical Isolation:** Separates networks from the internet for enhanced security.
- **Logical Segmentation:** Uses VLANs and subnetting for better control and containment.
- **Software-Defined Networking (SDN):** Centralizes control but requires secure management.

**6. On-premises:** Directly controls security within the organization's facilities but needs comprehensive in-house measures.

**7. Centralized vs. Decentralized:**
- **Centralized:** Simplifies management but can be a single point of failure.
- **Decentralized:** Enhances redundancy but complicates security enforcement.

**8. Containerization:** Isolates applications for consistent environments and improved security.

**9. Virtualization:** Runs multiple virtual environments on one server, enhancing security through isolation.

**10. IoT:** Connects many devices, requiring strong device-level security.

**11. ICS/SCADA:** Manages critical infrastructure with stringent security measures.

**12. RTOS:** Manages time-sensitive applications, ensuring reliability and low latency.

**13. Embedded Systems:** Integrates hardware and software with built-in security due to limited update capability.

**14. High Availability:** Uses redundancy and fault tolerance to maintain operations during disruptions.

## Considerations
- **Availability:** Ensures continuous system operation.
- **Resilience:** Enables recovery from disruptions.
- **Cost:** Balances security measures with budget constraints.
- **Responsiveness:** Measures speed in adapting security measures.
- **Scalability:** Expands security as systems grow.
- **Ease of Deployment:** Simplifies implementation of security solutions.
- **Risk Transference:** Shifts risk to third parties.
- **Ease of Recovery:** Facilitates restoration after a breach.
- **Patch Availability:** Ensures timely updates for vulnerabilities.
- **Inability to Patch:** Implements alternative measures for unpatchable systems.
- **Power:** Ensures reliable supply for critical systems.
- **Compute:** Provides adequate processing power for security operations.

## Applying Security Principles to Secure Enterprise Infrastructure
- **Device Placement:** Positions devices strategically for security and efficiency.
- **Security Zones:** Segments networks into different security levels.
- **Attack Surface:** Minimizes entry points for attackers.
- **Connectivity:** Manages and secures network connections.
- **Failure Modes:** Decides between fail-open (continuity) or fail-closed (security).
- **Device Attribute:** Differentiates between active/passive and inline/tap/monitor devices.
- **Network Appliances:** Includes jump servers, proxy servers, IPS/IDS, load balancers, and sensors for various security functions.

## Secure Communication/Access
- **VPN:** Secures remote access with encryption.
- **Remote Access:** Enables secure access from remote locations.
- **Tunneling:** Uses TLS and IPSec for secure data transmission.
- **SD-WAN:** Manages and secures WAN connections through centralized control.
- **SASE:** Combines network security and WAN capabilities in a cloud model.

## Selecting Effective Controls
- **Purpose:** Choose appropriate controls to protect infrastructure.
- **Benefits:** Ensures controls effectively mitigate risks.

## Comparing Data Protection Strategies
- **Data Types:** Includes regulated, trade secrets, intellectual property, legal, financial, and human/non-human-readable data with specific protection strategies.
- **Data Classifications:** Ranges from sensitive to critical data with corresponding protection methods.
- **Data States:** Includes at rest, in transit, and in use with relevant protection strategies.
- **Data Sovereignty and Geolocation:** Ensures compliance with local laws and regional data protection regulations.

## Methods to Secure Data
- **Geographic Restrictions:** Limits access based on location.
- **Encryption:** Secures data confidentiality and integrity.
- **Hashing:** Ensures data integrity.
- **Masking:** Conceals sensitive data within datasets.
- **Tokenization:** Replaces sensitive data with tokens.
- **Obfuscation:** Makes data difficult to understand.
- **Segmentation:** Divides data into segments to limit access.
- **Permission Restrictions:** Controls data access and modification.

## Importance of Resilience and Recovery
- **High Availability:** Includes load balancing and clustering for performance and redundancy.
- **Site Considerations:** Hot, cold, and warm sites for backup and recovery.
- **Platform Diversity:** Uses multiple platforms to avoid single points of failure.
- **Multi-Cloud Systems:** Distributes workloads across different cloud providers for resilience.
- **Continuity of Operations:** Ensures critical functions continue during and after a disaster.
- **Capacity Planning:** Ensures sufficient people, technology, and infrastructure for recovery.
- **Testing:** Includes tabletop exercises and failover testing to improve response and recovery.
