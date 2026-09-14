# Deepfake Video & Synthetic Media Scams

## Overview
Deepfake fraud employs deep generative neural networks (such as GANs, diffusion models, and autoencoders) to synthesize hyper-realistic video and audio of individuals, creating fabricated visual evidence and deceiving victims during live video conferences.

## High-Risk Scenarios
1. **Live Corporate Video Call Fraud**:
   - Attackers attend multi-person Zoom or Teams meetings using real-time deepfake face and voice swaps of the company's Chief Financial Officer (CFO), instructing colleagues to execute multi-million-dollar wire transfers (e.g., the $25M Hong Kong multinational heist).
2. **Fabricated Extortion & Blackmail**:
   - Threat actors crop photos from social media and superimpose victims' faces onto explicit or compromising video footage, demanding ransom via cryptocurrency to prevent public distribution.
3. **Celebrity Investment Endorsement Fraud**:
   - Deepfaked videos of business figures (e.g., Elon Musk, Mukesh Ambani, Narayana Murthy) promoting non-existent automated trading algorithms or government investment initiatives.

## Technical & Visual Forensic Indicators
- **Boundary & Blending Discrepancies**: Subtle blurring, warping, or skin-tone mismatch along the jawline, neck, and hair boundaries.
- **Unnatural Blinking & Eye Movement**: Lack of natural blinking frequency or mismatched eye reflections (specular highlights).
- **Spectral Frequency Anomalies**: High-frequency grid noise introduced by generative neural upsampling detectable via 2D Fast Fourier Transform (FFT) analysis.
- **Temporal Inconsistency**: Flickering or sudden shape deformations when the subject moves their head rapidly or passes a hand in front of their face.

## Verification Tactics
- Ask the participant during a live call to turn their head sideways at a 90-degree angle or wave their fingers across their face; real-time face-swap models fail and distort severely on profile angles.
- Establish out-of-band verification via a known secondary telephone channel before executing sensitive financial or credential transactions.
