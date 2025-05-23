
from http import client
from fastapi import FastAPI
import pymongo
import requests
import httpx
import datetime

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

        # checks if the CVE in the db if not add
        count = 0;
        for x in cves:
            cve_id = x['cve']['id']
            print(cve_id)
            cve_id = str(cve_id)
            if (mycollection.find_one({"cve.id":cve_id})):
                continue
            else:
                mycollection.insert_one(x)
                count+=1
        return {f"Synced {count} CVEs"}


# Search with cve-id in path paramenter
@app.get("/cve/id/{id}")
def get_by_id(id:str):
    print(id)
    search_cve = mycollection.find_one({"cve.id":id})
    if (search_cve):
        for cve in search_cve:
            cve["_id"] = str(cve["_id"])
        return search_cve
    return {f"No CVE found with {id}"}

# Search with cve-id with query parameter
@app.get("/cve/search/")
def get_by_id_q(id:str):
    #print(type(id))
    search_cve = mycollection.find_one({"cve.id":id})
    if (search_cve):
        for cve in search_cve:
            cve["_id"] = str(cve["_id"])
        return str(search_cve)
    else:
        return {f"No CVE found with {id}"}

# Get by Year
@app.get("/cve/year/{year}")
def get_by_year(year:str):
    year_date = datetime.date(int(year),1,1)
    year_date_next = datetime.date(int(year)+1,1,1)

    year_iso = year_date.isoformat()
    year_iso_next = year_date_next.isoformat()

    print(year_iso,year_iso_next)

    query = {"cve.published":{"$gt":year_iso,"$lt":year_iso_next}}
    search_cve = list(mycollection.find(query))
    for cve in search_cve:
        cve["_id"] = str(cve["_id"])

    return search_cve

# get by range of year
@app.get("/cve/year/")
def get_by_year_(year1:str,year2:str):
    year_date = datetime.date(int(year1),1,1)
    year_date_th = datetime.date(int(year2),1,1)

    year_iso1 = year_date.isoformat()
    year_iso2 = year_date_th.isoformat()



    if (year1 > year2):
        query = {"cve.published":{"$gt":year_iso2,"$lt":year_iso1}}
        search_cve = list(mycollection.find(query))
        for cve in search_cve:
            cve["_id"] = str(cve["_id"])
        return search_cve
    else:
        query = {"cve.published":{"$gt":year_iso1,"$lt":year_iso2}}
        search_cve = list(mycollection.find(query))
        for cve in search_cve:
            cve["_id"] = str(cve["_id"])
        return search_cve


# get by baseScore
@app.get("/score/{score}")
def get_by_score(score:int):
    query1 = {"cve.metrics.cvssMetricV2.cvssData.baseScore":score}

    search_cve = list(mycollection.find(query1))

    for cve in search_cve:
        cve["_id"] = str(cve["_id"])

    if (search_cve):
        return search_cve

    return f"No records Found with BaseScore {score}"


# get by Last N days
@app.get("/cve/last/{N}")
def search_by_N(N:int):
    today = datetime.date.today().isoformat()
    x = datetime.date.today() - datetime.timedelta(N)
    x = x.isoformat()
    query = {"cve.lastModified":{"$gt":x,"$lt":today}}
    search_cve = list(mycollection.find(query))

    for cve in search_cve:
        cve["_id"] = str(cve["_id"])

    if (search_cve):
        return search_cve
    return {"No results Found"}




@app.get("/")
def homepage():
    return  {"msg":"HomePage"}



if __name__ ==  "__main__":
    import uvicorn
    uvicorn.run(app,host="0.0.0.0",port=8000)
