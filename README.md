# APSA: Auditable Private Stream Aggregation

## Overview
This repository contains the source code and experimental data for the research paper titled "APSA: Auditable Private Stream Aggregation." The paper is currently under review for publication.

## Repository Structure
- **Network**: Data related to the performance testing of network capabilities.
- **Optimization**: Data demonstrating the effects of NTT optimizations on the APSA protocol.
- **Space**: Data on the optimization of proof sizes using NIZK.
- **Test**: A collection of simple test cases.
- **Code**: Core implementation of the APSA protocol along with associated testing code.
- **Dimension**: Data examining the impact of data sizes on APSA's efficiency.
- **Origin**: Comprehensive results from all tests performed on the APSA protocol, including performance tests and applications in AI, e-voting, and social surveys. Results are presented in tables and charts using the Origin software.

## How to Use

This section outlines how to use the key components of the APSA project. Each module serves a specific role within the framework and can be executed according to the following descriptions:

- **Main**: This is the primary entry point of the APSA protocol. Start the application by running the Main function, which integrates all components of the APSA workflow.

- **RLWE**: Implements the Ring Learning With Errors (RLWE) encryption scheme. Use this module to perform secure, noise-based encryption necessary for the APSA operations.

- **L_2_norm**: Utilizes zero-knowledge proofs to establish bounds on the L2 norm. This module is critical for ensuring the integrity and confidentiality of the data aggregation process.

- **L_infty_norm**: Implements zero-knowledge proofs for the $L_{\infty}$ norm bounds. This ensures that data stays within predefined limits, enhancing security and reliability.

- **User**: Contains the operations that need to be performed by the user side in the APSA protocol. This includes data submission and initial processing steps.

- **Aggregator**: Manages the aggregation operations required in the APSA protocol. This module is responsible for collecting and processing data from multiple users securely.

- **well-formedness_proof**: Provides functionality to verify the well-formedness of key structures. Essential for maintaining the security properties of the cryptographic components.

- **Ring_polynomial**: Implements ring polynomial encoding. This module is used for complex mathematical operations that underpin the cryptography in APSA.

- **config**: Manages APSA configuration settings. Adjust parameters and settings by editing the configurations in this module before running the application.

## Contributing
Contributions to the APSA project are welcome. Please submit a pull request or open an issue to discuss potential changes or improvements.

## Citation
If you use this code or the APSA protocol in your research, please cite our paper as follows:
```bibtex
@unpublished{APSA2024,
  title={APSA: Auditable Private Stream Aggregation},
  author={Author Names},
  note={Manuscript under review}
}
```
