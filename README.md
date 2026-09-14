<div align="center">

# 🛡️ SatyaAI 3.0

### Multimodal AI Cyber Fraud & Deepfake Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?logo=fastapi)](https://fastapi.tiangolo.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-satyaai__db-blue?logo=postgresql)](https://www.postgresql.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*Detect phishing, vishing, email scams, deepfakes & more — in real-time.*

</div>

---

## ✨ Features

| Modality | Capability |
|---|---|
| 💬 **Message** | NLP-based scam/fraud text detection |
| 🔗 **URL** | Phishing URL analysis with geolocation |
| 📧 **Email** | Header spoofing, SPF/DKIM/DMARC, credential harvesting |
| 📸 **Image** | OCR + visual scam content extraction |
| 🎵 **Audio** | Whisper transcription + vishing detection |
| 📹 **Video** | Deepfake frame analysis (YuNet face detection) |
| 📞 **Call** | Call transcript vishing & OTP extortion detection |

**Additional:**
- 🗺️ **Live Threat Origin Map** — Geolocates threat infrastructure in real-time
- 🤖 **AI Fraud Investigation Copilot** — RAG-powered Q&A on uploaded evidence
- 🧠 **Explainable AI** — Evidence breakdown, attacker goals, recommended actions
- 🗄️ **PostgreSQL Persistence** — All analyses stored in `satyaai_db`

---

## 🏗️ Architecture

```
Frontend (Vanilla JS/CSS)
        │
        ▼
FastAPI Backend (Python 3.11)
        │
   ┌────┴────────────────────────────────────────┐
   │                                             │
AI/ML Services                         Database (PostgreSQL)
   ├── message_service.py               backend/database/
   ├── url_service.py                   ├── database.py
   ├── email_service.py                 ├── models.py
   ├── audio_service.py                 └── schemas.py
   ├── deepfake_service.py
   ├── call_service.py
   ├── geolocation_service.py
   └── chat_service.py (Copilot)
```

---

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/jprathmesh1217-jpg/satyaai-3.0.git
cd satyaai-3.0

# Create virtualenv
python3.11 -m venv venv311
source venv311/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your DATABASE_URL
```

`.env` format:
```
DATABASE_URL=postgresql://localhost:5432/satyaai_db
```

### 3. Setup PostgreSQL

```bash
createdb satyaai_db
# Tables are auto-created on first startup
```

### 4. Run

```bash
python -m uvicorn backend.main:app --reload
```

Open **http://127.0.0.1:8000/app** in your browser.

---

## 📡 API Endpoints

### Analysis
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/analyze/message` | Text scam analysis |
| POST | `/api/analyze/url` | URL phishing check |
| POST | `/api/analyze/email` | Email threat analysis |
| POST | `/api/analyze/email/file` | Upload `.eml` file |
| POST | `/api/analyze/image` | Image OCR + scam detection |
| POST | `/api/analyze/audio` | Audio transcription + analysis |
| POST | `/api/analyze/video` | Deepfake video analysis |
| POST | `/api/analyze/call` | Call audio vishing detection |
| POST | `/api/analyze/call/text` | Call transcript analysis |

### Database
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/analyses` | List all analyses |
| GET | `/api/analyses/{id}` | Get analysis by ID |
| GET | `/api/analyses/stats/summary` | Aggregate stats |

### Copilot
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/chat/upload` | Upload evidence for investigation |
| POST | `/api/chat` | Chat with AI Copilot |

---

## 🛠️ Tech Stack

- **Backend**: FastAPI, Python 3.11, Uvicorn
- **ML/AI**: scikit-learn, OpenCV (YuNet), OpenAI Whisper, pytesseract
- **Database**: PostgreSQL, SQLAlchemy, psycopg2-binary
- **Frontend**: Vanilla JS, CSS3, Leaflet.js (maps)
- **NLP**: Sentence Transformers, TF-IDF

---

## 🧪 Tests

```bash
pytest tests/ -v
```

---

## 📁 Project Structure

```
satyaai-3.0/
├── backend/
│   ├── main.py                  # FastAPI app + all routes
│   ├── database/                # PostgreSQL integration
│   ├── services/                # AI/ML service modules
│   └── knowledge_base/          # RAG knowledge documents
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
├── models/                      # Trained ML model files
└── tests/                       # Test suite
```

---

## ⚠️ Important Notes

- **`.env` is excluded from git** — never commit your database credentials
- Models are lightweight (< 1MB each) and committed to the repo
- The database persistence layer is **non-blocking** — if PostgreSQL is offline, analyses still work

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built with ❤️ by <strong>Prathamesh</strong>
</div>
