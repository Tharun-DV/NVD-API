# NVD-API

A FastAPI-powered REST API for querying CVE (Common Vulnerabilities and Exposures) data from the National Vulnerability Database (NVD) with MongoDB storage. Designed for security researchers and developers to programmatically access vulnerability information.

---

## **Features**

- **Automatic NVD Synchronization**: Sync latest CVEs from NVD's REST API
- **Advanced Querying**: Search by CVE ID, publication year, score, and date ranges
- **MongoDB Backend**: Scalable NoSQL storage for vulnerability data
- **RESTful Endpoints**: Easy integration with security tools and workflows
- **Pagination Support**: Built-in MongoDB cursor handling for large datasets
- **Date Filtering**: Search by last N days or custom date ranges

---

## **Tech Stack**

- **Python 3.8+**
- **FastAPI** (Web Framework)
- **MongoDB** (Database)
- **httpx** (Async HTTP Client)
- **Pymongo** (MongoDB Driver)

---

## **Getting Started**

### **Prerequisites**
- Python 3.8+
- MongoDB (running locally on port 27017)

### **Installation**
```bash
git clone https://github.com/tharun-dv/NVD-API.git cve-api
cd cve-api
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### **Environment Variables**
Create `.env` file:
```env
MONGODB_URL=mongodb://localhost:27017
```

---

## **Endpoints**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sync` | GET | Sync latest CVEs from NVD |
| `/find` | GET | Get first 100 CVEs |
| `/cve/id/{id}` | GET | Get CVE by ID (path param) |
| `/cve/search/?id=CVE-...` | GET | Get CVE by ID (query param) |
| `/cve/year/{year}` | GET | Get CVEs by publication year |
| `/cve/year/?year1=YYYY&year2=YYYY` | GET | Get CVEs between years |
| `/score/{score}` | GET | Get CVEs by CVSS base score |
| `/cve/last/{N}` | GET | Get CVEs modified in last N days |

---

## **Usage**

### **Sync NVD Data**
```bash
curl -X GET "http://localhost:8000/sync"
```
```json
{"message":"Synced 50 CVEs"}
```

### **Search CVE by ID**
```bash
curl "http://localhost:8000/cve/id/CVE-2023-1234"
```
```json
{
  "_id": "64f1a2b3...",
  "cve": {
    "id": "CVE-2023-1234",
    "published": "2023-01-01T00:00Z",
    "metrics": {
      "cvssMetricV2": [
        {
          "cvssData": {
            "baseScore": 7.5
          }
        }
      ]
    }
  }
}
```

### **Get Recent CVEs**
```bash
curl "http://localhost:8000/cve/last/7"
```

---

## **Configuration**

- **Rate Limiting**: Default 5 requests/second (NVD public limit)
- **Pagination**: MongoDB's native cursor handling (modify queries as needed)
- **Storage**: All CVEs stored in `Exploits.CVEs` collection
- **Indexing**: Recommended to create indexes on:
  ```python
  db.CVEs.create_index("cve.id")
  db.CVEs.create_index("cve.published")
  ```

---

## **Development**

### **Run Locally**
```bash
uvicorn main:app --reload
```

### **Build Docker Image**
```bash
docker build -t cve-api .
docker run -p 8000:8000 cve-api
```

---

## **License**

MIT License

---

## **Security Considerations**

1. **Data Freshness**: NVD updates occur every 2 hours - sync regularly
2. **Rate Limiting**: Add API gateway for production deployments
3. **Authentication**: Implement API key auth for sensitive deployments
4. **Data Validation**: Validate all NVD responses before storage
