# FileCrypt

## What This Is

A desktop application for encrypting and decrypting any file type using password-based encryption. Built for personal use to secure files before uploading to cloud storage (Google Drive, Dropbox). Minimal UI with drag-and-drop workflow.

## Core Value

Only the user with the correct password can decrypt and read the encrypted files — strong encryption that's simple to use.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] User can encrypt any file by dragging it into the app
- [ ] User can decrypt encrypted files with the correct password
- [ ] Encrypted files cannot be read without the password
- [ ] App works on macOS (primary target)
- [ ] Encryption uses AES-256-GCM with Argon2id key derivation

### Out of Scope

- Mobile apps — desktop only for v1
- Cloud storage integration — manual upload after encrypt
- File sync/sharing features — this is an encryption tool only
- Password storage/management — user must remember passwords
- Multi-user/collaboration — single user tool

## Context

**Use case:** User has sensitive files (documents, images, any file type) that they want to store on cloud services (Google Drive, Dropbox) but want to ensure only they can access the content. The solution is encrypt-before-upload.

**Key decisions from questioning:**
- Desktop app (not web/CLI/mobile)
- Drag-and-drop workflow for simplicity
- Python + PyQt for tech stack (user preference)
- Paranoid-level security: AES-256-GCM + Argon2id key derivation
- Minimal feature set — just encrypt/decrypt, nothing else
- User manages passwords themselves (no storage in app)

## Constraints

- **Platform:** macOS primary target (user is on macOS)
- **Tech Stack:** Python + PyQt (user preference)
- **Security:** AES-256-GCM for encryption, Argon2id for key derivation (paranoid level)
- **Distribution:** Standalone desktop application
- **File Size:** Should handle files up to several GB (streaming encryption for large files)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Python + PyQt | User preference, rapid development | — Pending |
| AES-256-GCM | Industry standard, authenticated encryption, fast | — Pending |
| Argon2id key derivation | Memory-hard, resistant to GPU/ASIC attacks | — Pending |
| No password storage | Simpler, user takes responsibility | — Pending |
| Drag-and-drop UI | Minimal friction workflow | — Pending |

---
*Last updated: 2026-02-26 after initialization*
