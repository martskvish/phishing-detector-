import whois
from datetime import datetime, timezone

def WHOIS_lookup(domain):
    try:
        #Get raw text of domain's infomation, than python-whois parses that raw text into a Python object
        domaininfo = whois.whois(domain)

        #Get creation day of the domain from domaininfo.
        #Check if the creation is a list, sometimes creation_date returns a list with two elements.
        #Use datetime to get the difference of days from now to when the domain was created.
        #Newly registered = suspicious
        creation = domaininfo.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        domain_age = (datetime.now(timezone.utc) - creation).days if creation else None

        #Get the expiration day of the domain.
        #Check if the returned datatype is a list.
        #Find the difference between the expiration and creation dates in days.
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
        #Recent changes = suspicious.
        Updated = domaininfo.updated_date
        if isinstance(Updated, list):
            Updated = Updated[0]  # reassign back to the same variable
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
            reasons.append(f"Last updated {days_from_last_update} days ago (-5)")

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
    except Exception as e:
        print(f"Error: {e}")
        
        #Return empty values to keep other parts of program from crashing
        return 0, []
    

def SSL_certificate_analysis(domain):

    
    return