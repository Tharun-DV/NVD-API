from http import client
from fastapi import FastAPI
import pymongo
import requests
import httpx

app = FastAPI()
myclient = pymongo.MongoClient("mongodb://localhost:27017")
mydb = myclient["Exploits"]
mycollection = mydb["CVEs"]


# @app.on_event("startup")
# async def connect_db():
#     pass
#     print("Trying to connect to Monogodb")

# @app.on_event("shutdown")
# async def disconnect_db():
#     pass
#     print("Dissconnect from Monogdb")


@app.get("/sync")
async def sync():
    print("Trying to sync db")
    api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async with httpx.AsyncClient(timeout=None) as client:
        response = await client.get(api_url)
        report = response.json()
        cves = report["vulnerabilities"]


        # Inserts all the records into monogodb without checking if present
        #collect = mycollection.insert_many(cves)

        count = 0;
        for x in cves:
            cve_id = x['cve']['id']
            print(cve_id)
            cve_id = str(cve_id)
            if (mycollection.find({"cve.id":cve_id})):
                continue
            else:
                mycollection.insert_one(x)
                count+=1
        return {f"Synced {count} CVEs"}


@app.get("/")
def homepage():
    return  {"msg":"HomePage"}



if __name__ ==  "__main__":
    import uvicorn
    uvicorn.run(app,host="0.0.0.0",port=8000)
