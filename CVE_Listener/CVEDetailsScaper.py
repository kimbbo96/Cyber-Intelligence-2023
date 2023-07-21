#python2.7.x compiled on Python 2.7.10 :: Anaconda 2.3.0 (64-bit)
#CveDetailsScaper.py
#A small python script used for scraping the CVE Details website for collating the following information
# CVE-ID,Severity,Product,Vendor,Summary (Primary required fields, many additional fields shall be present)

from bs4 import BeautifulSoup
import requests,sys,datetime,re
from argparse import ArgumentParser
import json


confidentialityImpactTup=('Complete','None','Partial')
integrityImpactTup=('Complete','None','Partial')
availibilityImpactTup=('Complete','None','Partial')
accessComplexityTup=('Low','Medium','High') #Low means , accessible easily.
authenticationRequiredTup=('Not Required','Single System') #Single System implies that attacker requires a session.
accessLevelGainedTup=('None','Admin') #What is the access Level gained by exploiting this vulnerability

def parse_arguments(): # Function for parsing command line arguments
    parser = ArgumentParser(description='A small python script used for scraping the CVE Details website for collating the following information'+'\n'+'# CVE-ID,Severity,Product,Vendor,Summary (Primary required fields, many additional fields shall be present)')
    parser.add_argument('-smin',help='Minimum Severity Rating',default=7)
    parser.add_argument('-smax',help='Maximum Severity Rating',default=10)
    parser.add_argument('-mmin',help='Minimum Month in Number viz 1-12',default=datetime.date.today().month)
    parser.add_argument('-mmax',help='Maximum Month in Number viz 1-12',default=datetime.date.today().month)
    parser.add_argument('-y',help='Year in YYYY',default=datetime.date.today().year)
    args=parser.parse_args()
    return args

def createFullUrl(smin,smax,year,month,page)    :
    url = "http://www.cvedetails.com/vulnerability-list.php?vendor_id=0&product_id=0&version_id=0&page="+str(page)+"&cvssscoremin="+str(smin)+"&cvssscoremax="+str(smax)+"&year="+str(year)+"&month="+str(month)+"&order=3"
    return url

def getSoupHTML(url):
    response=requests.get(url)
    html=response.content
    soup = BeautifulSoup(html,"html.parser")
    #pprint.pprint(soup)
    return soup

def getCVEIds(soup,cveArray):
    table = soup.find('table',attrs={'class','searchresults'})
    for a in table.find_all('a',href=True):
        m = re.search("CVE-\d{4}-\d{4,7}",a['href'])
        if m:
            cveArray.append(m.group(0))

def getCVEPages(soup):
    cveIDPages=[]
    items=soup.find_all('div',class_="paging")
    for item in items:
        links=item.find_all('a')
        for link in links:
            cveIDPages.append("http://www.cvedetails.com/"+str(link['href']))

    return cveIDPages

def getCVEDetails(cveid=''):
    CVEDict ={}
    cveUrl='http://www.cvedetails.com/cve/'+cveid+'/'
    response = requests.get(cveUrl)
    cveHtml=response.content
    soup = BeautifulSoup(cveHtml,"html.parser")
    if soup =='':
        return None
    CVEDict["cveIDNumber"] = cveid
    table = soup.find(id='vulnprodstable')
    cvssTable = soup.find(id='cvssscorestable')
    summarySoup=soup.find('div',class_="cvedetailssummary")
    CVEDict["summaryText"] = summarySoup.text.split("\n")[1].strip()
    dateStr=summarySoup.text.split("\n")[3]
    split1 = dateStr.split("\t")
    if len(split1) < 2:
        return None
    split2 = split1[1].split(":")
    if len(split2) < 2:
        return None
    CVEDict["publishDate"] = split2[1].strip()

    productData=[]

    for row in table.findAll('tr')[::-1]: #Get only the last row
        cols=row.findAll('td')
        for i in range(len(cols)):
            productData.append(cols[i].text.strip())

    if len(productData) < 9:
        return None

    CVEDict["softwareType"] = productData[1].strip()
    CVEDict["vendor"] = productData[2].strip()
    CVEDict["product"] = productData[3].strip()
    CVEDict["version"] = productData[4].strip()
    cvssData=[]
    for row in cvssTable.findAll('tr'): #Get only the first row
        cols=row.findAll('td')
        for i in range(len(cols)):
            cvssData.append(cols[i].text.strip())
    CVEDict["cvssScore"] = cvssData[0]
    ci=cvssData[1].split("\n")[0]
    CVEDict["confidentialityImpact"] = ci.strip()
    ii=cvssData[2].split("\n")[0]
    CVEDict["integrityImpact"] = ii.strip()
    ai=cvssData[3].split("\n")[0]
    CVEDict["availibilityImpact"] = ai.strip()
    ac=cvssData[4].split("\n")[0]
    CVEDict["accessComplexity"] = ac.strip()
    ar=cvssData[5].split("\n")[0]
    CVEDict["authentication"] = ar.strip()
    al=cvssData[6].split("\n")[0]
    CVEDict["gainedAccess"] = al.strip()
    CVEDict["vulnType"] = cvssData[7].strip()

    return CVEDict


def main():

    args = parse_arguments()
    if args.y:
        year=args.y
    if args.smin:
        smin=args.smin
    if args.smax:
        smax=args.smax
    if args.mmin:
        month_min=int(args.mmin)
    if args.mmax:
        month_max=int(args.mmax)

    for n in range(month_min,month_max+1):
        fullUrl=createFullUrl(smin,smax,year,n,1)
        soupObject=getSoupHTML(fullUrl)
        cvePagesArray=getCVEPages(soupObject)
        cveArray=[]
        for cvePage in cvePagesArray:
            soupObject=getSoupHTML(cvePage)
            getCVEIds(soupObject,cveArray)

        count=0
        for cve in cveArray:
            my_dict = getCVEDetails(cve)
            count=count+1
            if my_dict != None:
                print(json.dumps(my_dict))

if __name__ == '__main__':
    status = main()
    sys.exit(status)
