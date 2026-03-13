import requests

def decompose_url(url):

    # initializes variables to store different components of the URL.
    protocol = ""
    domain = ""
    path = ""
    query = ""

    #check if the URL contains "://"
    #If it does, it splits the URL into two parts: the protocol ("https") and the remainder of the URL.
    if "://" in url:
        parts = url.split("://")
        protocol = parts[0]
        remainder = parts[1]
    else:
        #If the URL does not contain "://", it assumes there is no protocol specified and treats the entire URL as the remainder.
        remainder = url

    #This checks if the remainder of the URL contains a "/". 
    #If it does, it splits the remainder into the domain(0) and path(1) components.
    if "/" in remainder:
        domain = remainder.split("/")[0]
        #get the path part of the URL after the domain.
        path = remainder[len(domain):]
    else:
        #If there is no "/", it assumes the entire remainder is the domain and there is no path.
        domain = remainder


    #splits the path from the query parameters if there is a "?" in the path.
    if "?" in path:
        path_parts = path.split("?")
        path = path_parts[0]
        query = path_parts[1]

    #split domain into its components.
    domain_parts = domain.split(".")

    #The top-level domain (TLD) is typically the last part of the domain ("com", "org", "net").
    tld = domain_parts[-1]

    #if domain_parts conatisn 2 or more parts, the main domain is the second to last part ("example" in "www.example.com").
    if len(domain_parts) >= 2:
        main_domain = domain_parts[-2]
    else:
        #If the domain does not have at least two parts, it means there is no main domain, and we can set it to an empty string or handle it as needed. 
        #example: localhost or IP address.
        main_domain = ""
        tld = ""

    #extract subdomains (all parts except the last two).
    subdomains = domain_parts[:-2]

    #store extracted components in a dictionary for easy access.
    result = {"protocol": protocol,"domain": domain,"main_domain": main_domain,
        "tld": tld,"subdomains": subdomains,"path": path,"query": query}

    return result



def extraxt_html_content(url):
    #Send a GET request
    response = requests.get(url)

    #Check if the request was successful
    if response.status_code == 200:
        
        #Get the HTML content as text
        html_content = response.text

        #Print first 20000 characters
        print(html_content[:20000])  
    else:
        print(f"Failed to retrieve page. Status code: {response.status_code}")
    
    return response

url = "https://advertools.readthedocs.io/en/master/advertools.urlytics.html#analyzing-a-large-number-of-urls"
data = decompose_url(url)
data2 = extraxt_html_content(url)
print(data)
print(data2)
