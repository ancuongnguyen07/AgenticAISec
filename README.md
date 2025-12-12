
# SysSec-Crypt :heart: LLM-AgenticAI
This repo contains educational materials regarding LLM Agentic AI Security.
The language and technical terms used across this repo reflects the lens of
system security, and cryptography, through emerging security issues
raised by LLM models and LLM-integrated systems (Agentic systems).

If you have a solid background in system security and want to connect
your expertise into evolving agentic systems, I highly recommend you
take a look at this comprehensive survey [
"Systems Security Foundations for Agentic Computing
"](https://arxiv.org/abs/2512.01295).

This is my self-learning notebook that notes my thoughts while learning
agentic AI security. If you are also in the same ship (travel to agentic AI
island) and have the same toolbox (solid background in system security
or applied cryptography), I hope this repo is helpful along your journey.

*Note: this repo is still actively modified*

# LLM/AgenticAI security courses

## LLM courses
LLM foundation course, covering preliminaries for building a LLM,
from Stanford:
https://cme295.stanford.edu/

If you want to develop a Language Model (LM) by yourself, I highly recommend
this course from Stanford: https://stanford-cs336.github.io/spring2025/

LLM security course designed by Prof. Earlence Fernandes from UC San Diego:
https://cseweb.ucsd.edu/~efernandes/teaching/cse291wi25/cse291.html

## Agentic AI courses
A series of Agent Security courses designed by
Prof. Dawn Song from UC Berkeley:
- LLM Agents (Fall 2024): https://agenticai-learning.org/f24
- Advanced LLM Agents (Spring 2025): https://llmagents-learning.org/sp25
- Agentic AI (Fall 2025): https://agenticai-learning.org/f25

Trustworthy ML course, mainly covering LLM/AgenticAI topics, by Prof. John 
Mitchell from Stanford:
https://web.stanford.edu/class/cs329t/index.html#overview

# Premilinaries
## What is LLM?
Large Language Model (LLM) exel in a wide range of Natural Language
Processing (NLP) tasks (look at this [survey](https://www.researchgate.net/profile/Tang-Tianyi-3/publication/369740832_A_Survey_of_Large_Language_Models/links/665fd2e3637e4448a37dd281/A-Survey-of-Large-Language-Models.pdf)).
Given a prompt, an LLM tokenizes it into token-level embeddings and generates
a response token sequence in an autoregressive manner which maximize the
probability of tokens appeared in the response sequence. 

## What is Agentic AI?
Agentic AI is an autonomy system based LLM to automatically makes decisions
and executes task given the user's prompt. Unlike traditonal AI system,
which primarily response to commands, genrating text-based contents
regarding user's prompts, agentic AI can interact with external worlds,
websites, APIs, devices.

For example, a user can ask agentic AI to book a flight, including
searching suitable flights, reserve seats, and make a payment automatically
(without human intervention) given just a text command

# Current security threats
TOP 10 security risks for LLM-integrated applications from OWASP:
https://genai.owasp.org/llm-top-10/

According to the OWASP's report, *Prompt Injection* (PI),
or more specifically *Indirect Prompt Injection* (IPI), is cited as the 
#1 security threat.

## Prompt Injection
According to [Liu+2024](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-yupei),
IPI defense can be split into two types: detection
and prevention.

# State-of-the-art (SOTA) defense mechanisms

The table below summarizes what SOTA solutions to address IPI that I have
collected in the wild.

*Last updated: 12/12/2025*

|                                                                                     | Defense Type           | Level  | Determinism        | Model modification | Note                                                                                                                                                                                 |   |
|-------------------------------------------------------------------------------------|------------------------|--------|--------------------|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---|
| [AttentionTracker](https://aclanthology.org/2025.findings-naacl.123/)               | Detection              | Model  | :grey_question:    | :white_check_mark: | Utilize statistical attention patterns of user prompts                                                                                                                               |   |
| [PromptShield](https://arxiv.org/abs/2501.15145)                                    | Detection              | Model  | :grey_question:    | :x:                |                                                                                                                                                                                      |   |
| [TaskTracker](https://arxiv.org/abs/2406.00799)                                     | Detection              | Model  | :x:                | :x:                | Utilize LLM activations to detect task drift caused by IPI                                                                                                                           |   |
| [Spotlighting]( https://arxiv.org/abs/2403.14720)                                   | Prevention             | Prompt | :x:                | :x:                | Separate data and instruction through dedicated token (e.g., <>), or encoding (e.g., base64)                                                                                         |   |
| [SecAlign](https://dl.acm.org/doi/abs/10.1145/3719027.3744836)                      | Prevention             | Model  | :x:                | :white_check_mark: | Applying preference optimization technique during fine-tuning.                                                                                                                       |   |
| [StruQ](https://www.usenix.org/conference/usenixsecurity25/presentation/chen-sizhe) | Prevention             | Model  | :x:                | :white_check_mark: | Introduce additional LLM to separate user instructions from untrusted external data through distinct data processing channels                                                        |   |
| [RENNERVATE](https://arxiv.org/abs/2512.08417)                                      | Detection and Recovery | Token  | :grey_question:    | :x:                | Utilize attention feature at the token-level                                                                                                                                         |   |
| [IsolateGPT](https://arxiv.org/abs/2403.04960)                                      | Prevention             | System | :grey_question:    | :x:                | Isolate execution environments among applications, requires user interventions for potentially dangerous actions (such as cross-application interaction).                            |   |
| [f-secure](https://arxiv.org/abs/2409.19091)                                        | Prevention             | System | :white_check_mark: | :x:                | Propose an information-flow enforcement approach that requires manual pre-labelling of data sources as *trusted* or *untrusted*.                                                     |   |
| [CaMeL](https://arxiv.org/abs/2503.18813)                                           | Prevention             | System | :white_check_mark: | :x:                | Extracts control and data flows from trusted user queries and employs a custom interpreter to prevent untrusted data from affecting program flow.                                    |   |
| [Progent](https://arxiv.org/abs/2504.11703)                                         | Prevention             | System | :white_check_mark: | :x:                | Dynamically generate security policies at runtime, aka programmable security policy enforcement.                                                                                     |   |
| [GuardAgent](https://openreview.net/pdf?id=2nBcjCZrrP)                              | Prevention             | System | :grey_question:    | :x:                | *guardrails for LLM agents*. This is LLM *agent* designed to safeguard other LLM agents, which differs from several approaches utilizing *models* to safeguard *models* or *agents*. |   |

# Security challenges in applying security principles to agentic systems
Agentic systems have several challenges to apply time-tested security 
principles and mechanisms which are widely-deployed in traditional systems.

The following open issues are summarized from the survey [
"Systems Security Foundations for Agentic Computing"](https://arxiv.org/abs/2512.01295).

## Probabilistic TCB
The Trusted Computing Base (TCB) is an invariant element which is resistant
to attackers. In other words, it is the minimal secure component that we can
*blindly* trust to build additional defence mechanism ontop.

For example, in cryptography, the TCB is often the mathematical hard problem,
such as large integer factorization (RSA), discrete logarithm (Elliptic Curve 
Cryptography), or shortest vector problem (Lattice-based cryptography).

In system security literature, the TCB is often the hardware-enforced
security components (secure enclave), OS kernel, or reference monitors.

The above-mentioned TCB in traditional computing systems are deterministic
which means they behave predictably with the given parameters. However, in
LLM-powered computing systems, the TCB, which is the LLM model itself, behaves
*unpredictably*. The probabilistic nature of LLM models raises fundamental
challenges in transfering security principles in traditional systems into
the agentic systems:

1. A probabilistic LLM guardrail can detect 99% of malicious prompts, but 
possibly misses the remaining 1%. On the other hand, it can detect a benign
request as malicious as it has seen this pattern of request before (not 
included in its training dataset).
2. Formal methods, such as model/type checking, cannot be applied to a
undeterministic system.
3. LLM is vulnerable adversarial examples. It is even worser in multi-modal
models, in which data can be in several continuous representation spaces: 
audio, image, and video, rather than just text. Unfortunately, it is studied
that continuous space adversarial examples are easy to carry out (https://proceedings.mlr.press/v80/athalye18a.html). In traditional systems, discrete 
instruction sets with clear boundaries make attackers harder to craft
benign-looking but malicious requests. 

## Dynamic security policies, and privilege control
In traditional systems, code privilege, or permission, are managed by
security policies. For example, in Android, the app developer can select
a predefined set of permissions, provided by the OS, that his/her application
needs to assure functionality. Since the app serves for a fixed number of
purposes, the app developer can know in advance which permission is in needed
and present to the user at the time of installation. From the security
perspective, suspicious permission can be detected by analyzing the application,
infering from the apps's behaviours.

In agentic systems, the permission requirements are infered dynamically
per each task specified directly by a user, or indirectly through chain of
thoughts, through natural language. Hence, for each task, or each chain of
tasks, a new set of permissions must be generated in a secure manner to
assure that the agent has the minimal privilege to be able to complete the
task, complinant to the *least privilege principle*.

Two research packages to solve the above-mentioned dynamism:
1. Create Domain-specific Language (DSL) for different types of agents that are
applicable to formal reasoning.
1. Dynamic policy prediction from these DSL given user's input in natural 
language, including data from external untrusted source.

## Fuzzy security boundary
In traditional systems, there are absract layers sitting between trusted and
untrusted components to detect, filtering out malicious requests. Security
policies are often applied at these abstract layers. For example, the
process-kernel interface allows for SELinux-style MAC.

Two research packages to solve the above-mentioned lack of abstract layer:
1. Create an abstract layer so that security policies, or formal methods or
static analysis methods, are applicable. For example, let's have a planner
agent who will generate the code needs to be executed to complete the task
(this agent planner just plan the task to do, not calling function). Then
from the generated code, formal methods or static analysis can be applied
to make sure that there is no security issues and the code is able to
complete the task. Once the code is verified, the tool agent can call
functions to execute the given task.
2. Identify the right abstraction level in an existing agent design. In other
words, find the right position to place the abstract layer. For example,
in web browser agents, UI manipulation (e.g., mouse clicks and keystrokes)
can be executed by agents, but it does not make sense to place security
policies at those poorly-structured activities. Instead, the HTTP requests,
which is well-structured, is the reasonable choice for putting the abstract
layer on top.

## Prompt injections vs Dynamic Code Loading
Indirect Prompt Injection is a vulnerability designated for LLM-powered systems.
It has a counterpart in traditional systems, called Dynamic Code Loading (DCL).
DCL is a common in applications that support external plugins or extensions and
has raises challenges in terms of security. Widely-known issues originates from
DCL are SQL injection and JavaScript code injection, which are common in web
applications which is desirable to dynamically load extra scripts or data
based on user interaction or triggered events. To address these problems,
sandboxing and security policies are introduced. For example, Same-Origin
Policy only allows load additional scripts and data from 
URLs that have the same origin (root) from the current path. In terms of
sandboxing, browser isolates loaded pages/tabs so that each has its own
executing environment, avoiding unauthorized requests across pages/processes.

In agentic systems, security policies cannot applied due to the lack of
determinism of instruction. While in web environment, security policies are based
on URL which are deterministic, there is no such a concrete factor to
assess LLM outputs. Regarding sandboxing, recently there is an architecture
[IsolateGPT](https://www.ndss-symposium.org/ndss-paper/isolategpt-an-execution-isolation-architecture-for-llm-based-agentic-systems/)
which isolates execution for each tasks (including the task of planning).
The approach shown in **IsolateGPT** poses a promising direction in agent
isolation at task-level. 

# Open research directions
According to the survey [
"Systems Security Foundations for Agentic Computing"](https://arxiv.org/abs/2512.01295), research directions can be divided into
two categories: *specific mechanism* and *fundamental topics*.
*Specific mechanism* refers to defense mechanism such that if reliable and
trustworthy then can solve a considerable number of security and privacy
issues facing current agentic deployments. On the other hand, *fundamental 
topics* refer to long-term solutions that enhance the security and privacy
guarantees in future agentic deployments.

## Mechanism: Separating Instruction and Data
Instruction embedded in data is the root cause of prompt injection, the agent
is not able to distinguish which one is the specififed instruction for doing
tasks and which one is the data that should be treated as parameters or
conversation context.
In SQL injection, the problem is similar where the attacker feeds the SQL query
(intruction) in the place which is supposed to be data.

In traditional systems, the principle "W XOR X" that defines a particular memory
area is only writable (W) or executable (X) but not both. Given that principle,
one can define a particular space only for data (writable only) and another space
for instruction (executable only) which substantially degrade the type of
instruction-data-mixing attack.

However, the blur boundary between instruction and data is even worser in agentic
systems due to the inference of LLM models. LLM-based application is supposed to
derive a new task (an underspecified task) to satisfy an (underspecified) goal.
Please note that this is a desirable function of agentic systems in which user
does not need to *fully* specify chain of tasks to achieve the final goal (a
user only needs to specify the ultimate goal and sources of data, or data 
itself, that assist the agent to achieve the given goal).
Since the new tasks can be derived from the unstrusted data sources (e.g.,
PDF file, email, website), the isolation is hard to define without affecting
the accuracy of task functionality.

In agentic systems, there is no current models or LLM-based architecture that 
have a dedicated mechanism for such that instruction-data isolation. Recently,
the first [formal model of instruction-data separation](https://dl.acm.org/doi/abs/10.1145/3605764.3623985) has been proposed, but it does not equip a
systematic approach to mitigate this kind of issue. The paper introduces some
heuristic, post-hoc mitigation, but significantly reduces the functionality of
LLM-based applications. However, the proposed model can serve as the baseline,
an evaluation framework, and a wake-up call for research community to actively 
further investigate this fundamental issue in the future.

Unfortunately, it seems that even the isolation issue is solved, the malicious
instruction embedded in data can have negative effect on the data context that
feeds to the agent. [Poisoning attack](https://arxiv.org/abs/2508.20412) is
a prime example. This kind of attack "teachs" the agents to make mistakes
through malicious "canonical examples" in tool description.

## Mechanism: Access Control and Least Privilege
Access Control and Privilege Management have been commonly applied in traditional
systems to enhance security. For example, in Android, applications are granted
a sandboxed filesystem for their own without overlapping the others or OS's
filesystem. The application has read-write access only to the granted filesystem
but not the entire filesystem. Another example, the access control policy applied
at the OS kernel regarding to syscalls from user space, where a developer can
assure that resources from kernel are accessed from the user space (unstrusted
source) with the minimal privilege (the user has the least privilege to access
resources needed for its computation).

In agentic systems, it is not straightforward to apply the same principle. Agent
typically has a uniform access to all available tools. There is no such a notion
of program/application in agentic systems since LLM itself represents all 
possible programs at once. There is no "app developer" to set access control
policies, there is only user who prompts the agent through natural language.
*Currently, AI-agent providers recommend users to enforce policies manually
through prompting*.

A viable solution is to have a concrete security policy specification, then
have a reasoning LLM assistant to generate policies, compliant to the defined
specification, based on tasks given by the user. User interference can be a
good choice if a critical approval should be made, but it degrades the usability
of LLM-integrated systems (LLM-based systems is born to help users get free
from boring/repeated tasks).

## Mechanism: Information-Flow Control
Access control is a "on/off" switch that allows an agent has access to
particular resources or tools. In many cases, the agent needs access to
a specific resource, or tool, for just a particular task (a function call)
but not all other calls (similar to the dynamic permission control of Android
in which a mobile app can request a permission per specific task, a user
will be prompted "Allow only for this time"). For example, a coding agent needs 
access to
API keys to perform operations like uploading Docker container image to
the endpoint. In such cases, the access-control policy will state that
the agent has a legitimate reason to access such that sensitive information.
Following the *Least Privilege* principle, the agent must use that information
for *only* uploading Docker image but nothing else. There should be a
mechannism to guarantee that the flow of sensitive information (API key
in the example) indeed transmit from the agent to the endpoint.
This is where information-flow control (IFC) comes to play.

The IFC works by labelling data. By tracking labelled-data and enforcing
label-based policy, the system can assure that the data flow travels
as it is expected. The mechanism behind labeling and tracking is
[flow arithmetic](https://dl.acm.org/doi/pdf/10.1145/360051.360056).
Labeling and tracking can be done at many granularities, such as
processor-instruction level, program-variable level, filesystem-level,
cross-computer level.

In LLM-based systems, it is still an open problem to perform flow arithmetic
on data fed into LLMs since there is no discrete boundary between types of data
(they are all tokens under LLM). Hence, every piece of data could be labeled
as "everything", leading the issue of label exploision.

## Long-term: Security Guarantees from Probabilistic TCB
At the core level, the LLM itself is probabilistic, so a patient and
determined attacker can bypass security guards that LLM-based application
equips (thereotically an attacker can agressively generate malicious prompt or does
prompt optimization to bypass).

The problem is further complicated by the requirement that the probabilistic TCB
must be resistant under Byzantine assumptions, meaning that worst-case
attackers (adaptive, non-rational, not computationally bounded).

Another problem is that the AI agent itself may counterintuively try to evade
the security policy due to their propensity to [reward hacking](https://arxiv.org/abs/2502.13295)

## Long-term: Security-Aware Model Architecture
Until now, the common approaches place security enhancement outside the agent
(at system level) or retrain the agent to deal with security-aware tasks (at
model level). Another alternative may be to substantially enhance an already
trainedagent to enforce some security policy. If a circuit in the model is
found to address security-relevant aspect of a task and the security policy
blocks that aspect under some condition, it may be possible to enhance that
circuit to discard its outputs when condition holds, as proposed in
[AttentionTracker](https://aclanthology.org/2025.findings-naacl.123/).