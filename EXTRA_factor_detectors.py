#whois library used to retrieve domain registration information (registration date, expiration date, registrar, name servers).
#datetime and timezones are used verify and check registration and expiration dates of domain.
#requests are used to retrive and send requests to websites 
#requests.exceptions import specific errors types to detect specific errors after atempt to retrive SSL certificate.
import whois
from datetime import datetime, timezone
import requests
from requests.exceptions import SSLError, ConnectionError
from URL_extraction_analysis import decompose_url
def WHOIS_lookup(domain):
    try:
        #Get raw text of domain's infomation, than python-whois parses that raw text into a Python object
        domaininfo = whois.whois(domain)

        #Get creation day of the domain from domaininfo.
        #Check if the creation is a list, sometimes creation_date returns a list with two elements.
        #Use datetime to get the difference of days from now to when the domain was created.
        #If creation hase no value, set domain_age to None to handle it later in the code.
        #Newly registered = suspicious
        creation = domaininfo.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        domain_age = (datetime.now(timezone.utc) - creation).days if creation else None

        #Get the expiration day of the domain.
        #Check if the returned datatype is a list.
        #Find the difference between the expiration and creation dates in days.
        #If there is no expiration date or creation date, set registrated_for to None.
        #Only 1 year = suspicious.
        Expiration = domaininfo.expiration_date
        if isinstance(Expiration, list):
            Expiration = Expiration[0]
        registrated_for = (Expiration - creation).days if Expiration and creation else None

        #Get name servers
        Name_Servers = domaininfo.name_servers

        #Get registrar
        registrar = domaininfo.registrar

        #Get when the domain was last updated.
        #Check if the returned datatype is a list.
        #If Updtated has no value, set days_from_last_update to None.
        #Recent changes = suspicious.
        Updated = domaininfo.updated_date
        if isinstance(Updated, list):
            Updated = Updated[0]  #Reassign back to the same variable
        days_from_last_update = (datetime.now(timezone.utc) - Updated).days if Updated else None

        #Initilaize a score and reassons variables
        score = 0
        reasons = []

        #Domain age analysis 
        if domain_age is None:
            score = score + 15
            reasons.append("Domain age unknown (+15)")
        elif domain_age < 30:
            score = score + 40
            reasons.append(f"Very new domain: {domain_age} days (+40)")
        elif domain_age < 180: 
            score = score  + 15
            reasons.append(f"Young domain: {domain_age} days (+15)")
        elif domain_age < 1825: #5 years
            score = score - 10
            reasons.append(f"Old domain: {domain_age} days (-10)")
        else: #More than 5 years
            score = score - 15
            reasons.append(f"Very old domain: {domain_age} days (-15)")

        #Expiration period analysis
        if registrated_for is None:
            score = score + 10
            reasons.append("Registration duration unknown (+10)")
        elif registrated_for <365:
            score = score + 20
            reasons.append(f"Short registration: {registrated_for} days (+20)")
        elif registrated_for > 730: #More than 2 years
            score = score - 10
            reasons.append(f"Long registration: {registrated_for} days (-10)")

        #Last changes date analysis 
        if days_from_last_update is None:
            score = score + 5
            reasons.append("Last updated unknown (+5)")
        elif days_from_last_update < 7:
            score = score + 25
            reasons.append(f"Updated very recently: {days_from_last_update} days ago (+15)")
        elif days_from_last_update < 30:
            score = score +10
            reasons.append(f"Updated recently: {days_from_last_update} days ago (+10)")
        else: #Last updated more than 30 days ago
            score = score - 5
            reasons.append(f"Last updated: {days_from_last_update} days ago (-5)")

        #Statistics from https://docs.apwg.org/reports/apwg_trends_report_q3_2024.pdf
        SUSPICIOUS_REGISTRARS = {
        "namecheap, inc.",  #23.8% of BEC domains — largest after Squarespace
        "hostinger, uab",  #11.7% of BEC domains
        "godaddy.com, llc",  #4.5% of BEC domains
        "namesilo, llc", #2.2% of BEC domains
        "pdr ltd.", #2.2% of BEC domains
        "enom, llc",} #2.2% of BEC domains
        
        #Suspicious registrars analysis
        if registrar.lower () in SUSPICIOUS_REGISTRARS:
            score = score + 10
            reasons.append(f"Suspicious registrar: {registrar} (+10)")
        else:
            score = score + 5
            reasons.append("Registrar unknown (+5)")
        
        return score, reasons, Name_Servers, registrar
        
    #Catch any errors when whois.whois(domain) fails
    except Exception as error:
        print(f"Error: {error}")
        
        #Return empty values to keep other parts of program from crashing
        return 0, [], "", ""
    
def SSL_certificate_analysis(url):
    try:

        #Send a request to the website, tries to establish a secure HTTPS connection.
        #Timeout waits max for 7 seconds, to prevent program from freezing.
        #If SSL is valid, connection succeeds, retunrs "valid ssl".
        requests.get(url, timeout=7)
        return -10, "Valid SSL certificate (-10)"
    except SSLError:
        
        #When SSL error is detected, meaning that certificate is expired, self-signed or invalid making webiste suspicious.
        return 20, "Invalid SSL certificate (+20)" 
    except ConnectionError:

        #When connection error is detected, can mean that webiste is down or there is no intenet or domain doesn't exist.
        return 0, "Connection error, unable to verify SSL certificate (0)"
    except Exception:

        #Catch any other unexpected errors that may occur during the SSL certificate analysis. 
        return 0, "Error checking SSL certificate (0)"
    
def Openphish_API():
    #https://openphish.com/feed.txt stores a list of known phishing URLs that is updated every 12 hours.
    #Get the current date and time to track when the feed was last updated.
    #Open a text file to store the phishing URLs from Openphish feed.
    #Read all lines from the text file. 
    time_now =datetime.now()
    DB = open("DB\initialisators\phis_url.txt", "r") 
    Lines = DB.readlines()

    #Get the first line of the text file, which contains the last time the phishing url database was updated. 
    first_line = Lines[0].strip()
    stored_time = datetime.strptime(first_line, "%Y-%m-%d %H:%M:%S")

    #Convert to seconds.
    current_seconds = time_now.timestamp()
    stored_seconds = stored_time.timestamp()

    DB.close()
    #12 hours = 43200 seconds.
    if current_seconds >= stored_seconds + 43200:
        print("Refresh feed needed")

        try:
            response = requests.get("https://openphish.com/feed.txt", timeout=5)

            if response.status_code == 200:


                #Update first line with new time.
                Lines[0] = time_now.strftime("%Y-%m-%d %H:%M:%S") + "\n"
                
                #Open file in append mode to add new phishing URLs at the end of file.
                #Add previously stored phishing ULRs.
                #Add the phishing URLs from the Openphish feed to the text file.
                DB = open("DB\initialisators\phis_url.txt", "w")
                DB.writelines(Lines) 
                DB.write(response.text) 
                DB.close()

        except Exception as error:  
            print(f"Error fetching Openphish feed: {error}")
            return None    
    else:
        print("Feed still valid")
   
def COMP_DB_URL(current_url_domain):

    #Open the text file that contains phishing URLs with read mode.
    #skip first line
    DB = open("DB\initialisators\phis_url.txt", "r")
    next(DB)  

    #Strip to remove /n.
    #Compare the domain of current URL with the domains of phishing URls.
    #If match is found, break the loop and return +100 score and reason. If no match is found, return 0 score and reason.
    for line in DB:
        FOUND = False
        url = line.strip()

        decomposed_phish_url = decompose_url(url)
        if decomposed_phish_url["domain"] == current_url_domain:
            FOUND = True
            break
    DB.close()

    if FOUND:
        return 100, "Domain found in Openphish feed (+100)"
    else:
        return 0, "Domain not found in Openphish feed (0)"