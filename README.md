# Attack Chain Visualization

## High-Level Exploitation Flow

```mermaid
flowchart TD

A["Google Play Store APK"]
--> B["APK Decompilation"]

B --> C["Static Analysis"]
B --> D["Smali Enumeration"]
B --> E["Resource Extraction"]

E --> F["res/values/strings.xml"]
F --> G["Firebase API Key Extraction"]

D --> H["ChatActivity.smali"]
D --> I["MyFirebaseMessagingService.smali"]
D --> J["ManageAdminAdapter.smali"]

H --> K["Hardcoded Backend URLs"]
H --> L["Intent Handling Logic"]
H --> M["FCM Token Retrieval"]

I --> N["Firestore Token Storage Logic"]

J --> O["Role Update Architecture"]

K --> P["FastAPI Backend Recon"]

P --> Q["OpenAPI Enumeration"]

Q --> R["Unauthenticated Endpoints"]

R --> S["send-notification"]
R --> T["send-chat-notification"]
R --> U["send-agro-notification"]
R --> V["api/ask"]
R --> W["api/mental-support-chat"]

G --> X["Firebase Auth REST API"]

X --> Y["Create Arbitrary User Account"]

Y --> Z["Receive JWT idToken"]

Z --> AA["Authenticated Firestore Access"]

AA --> AB["Enumerate users Collection"]

AB --> AC["Read User Documents"]

AC --> AD["Extract fcmToken Values"]
AC --> AE["Extract role Values"]
AC --> AF["Extract PII"]

AD --> AG["Notification Hijack"]

S --> AG

AG --> AH["Send Notifications to Any User"]

AE --> AI["Identify Admin Accounts"]

AI --> AJ["Targeted Admin Notification Delivery"]

O --> AK["Potential Role Escalation Path"]

L --> AL["Potential Intent Injection Risk"]

style AG fill:#ff4d4d,color:#ffffff
style AJ fill:#ff4d4d,color:#ffffff
style AK fill:#ffcc00,color:#000000
style AL fill:#ffcc00,color:#000000
```

---

# APK Reverse Engineering Flow

```mermaid
flowchart LR

A["Production APK"]
--> B["apktool"]
--> C["Decoded Resources and Smali"]

C --> D["AndroidManifest.xml"]
C --> E["res/values/strings.xml"]
C --> F["ChatActivity.smali"]
C --> G["MyFirebaseMessagingService.smali"]
C --> H["ManageAdminAdapter.smali"]

E --> I["Firebase API Keys"]
E --> J["Project Configuration"]

F --> K["getIntent Calls"]
F --> L["getStringExtra Calls"]
F --> M["Hardcoded API URLs"]
F --> N["Firestore Reads"]
F --> O["fcmToken Access"]

G --> P["FCM Token Generation"]
G --> Q["Firestore Token Writes"]

H --> R["Direct Firestore Role Updates"]

style O fill:#ff4d4d,color:#ffffff
style R fill:#ffcc00,color:#000000
```

---

# Backend Attack Surface Mapping

```mermaid
flowchart TD

A["FastAPI Backend"]
--> B["openapi.json"]

B --> C["API Enumeration"]

C --> D["send-notification"]
C --> E["send-chat-notification"]
C --> F["send-agro-notification"]
C --> G["api/ask"]
C --> H["api/mental-support-chat"]
C --> I["analyze/image"]

D --> J["No Authentication"]
E --> J
F --> J
G --> J
H --> J
I --> J

J --> K["No JWT Validation"]
J --> L["No Firebase Token Verification"]
J --> M["No Rate Limiting"]

M --> N["Mass Notification Abuse"]
M --> O["API Quota Abuse"]

style J fill:#ff4d4d,color:#ffffff
style N fill:#ff4d4d,color:#ffffff
style O fill:#ffcc00,color:#000000
```

---

# Firestore Trust Boundary Failure

```mermaid
flowchart TD

A["Authenticated User"]
--> B["Firebase JWT"]

B --> C["Firestore users Collection"]

C --> D["Read Own Profile"]
C --> E["Read Other Users"]
C --> F["Read Admin Accounts"]
C --> G["Read fcmToken"]
C --> H["Read role"]
C --> I["Read PII"]

G --> J["Push Notification Targeting"]

H --> K["Potential Privilege Escalation"]

style E fill:#ff4d4d,color:#ffffff
style F fill:#ff4d4d,color:#ffffff
style G fill:#ff4d4d,color:#ffffff
style K fill:#ffcc00,color:#000000
```

---

# Notification Hijack Flow

```mermaid
sequenceDiagram

participant Attacker
participant APK
participant FirebaseAuth
participant Firestore
participant BackendAPI
participant FCM
participant Victim

Attacker->>APK: Decompile APK
APK->>Attacker: Firebase API Key

Attacker->>FirebaseAuth: Create Account
FirebaseAuth->>Attacker: JWT idToken

Attacker->>Firestore: Query users Collection
Firestore->>Attacker: User Documents + fcmToken

Attacker->>BackendAPI: POST send-notification
BackendAPI->>FCM: Forward Notification
FCM->>Victim: Push Notification Delivered
```

---

# Root Cause Relationship Map

```mermaid
flowchart TD

A["Weak Firestore Rules"]
--> D["FCM Token Exposure"]

B["Unauthenticated Backend APIs"]
--> E["Notification Delivery Abuse"]

C["FCM Tokens Stored with Profile Data"]
--> D

D --> F["Notification Hijack"]

E --> F

F --> G["Admin Targeting"]
F --> H["Spam Capability"]
F --> I["Social Engineering"]

style D fill:#ff4d4d,color:#ffffff
style E fill:#ff4d4d,color:#ffffff
style F fill:#ff0000,color:#ffffff
```

---

# Full End-to-End Kill Chain

```mermaid
flowchart TD

A["Download APK from Play Store"]
--> B["Decompile APK"]

B --> C["Extract Firebase Config"]
B --> D["Extract Backend URLs"]
B --> E["Analyze Smali"]

C --> F["Obtain Firebase API Key"]

F --> G["Create Account via REST API"]

G --> H["Receive Firebase JWT"]

H --> I["Access Firestore as Authenticated User"]

I --> J["Enumerate users Collection"]

J --> K["Read PII"]
J --> L["Read fcmToken"]
J --> M["Read role"]

L --> N["Target Arbitrary Device"]

D --> O["Enumerate Backend Endpoints"]

O --> P["Identify Unauthenticated Notification API"]

N --> Q["Submit Victim FCM Token"]

Q --> R["Push Notification Sent"]

R --> S["Victim Receives Fake Notification"]

M --> T["Identify Admin Accounts"]

T --> U["Deliver Admin-targeted Notifications"]

E --> V["Observe Role Update Logic"]

V --> W["Potential Privilege Escalation"]

style R fill:#ff0000,color:#ffffff
style S fill:#ff0000,color:#ffffff
style U fill:#ff0000,color:#ffffff
style W fill:#ffcc00,color:#000000
```
