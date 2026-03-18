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
        #If the URL does not contain "://", it assumes there is no protocol and entire URL is made as remainder.
        remainder = url

    #Check if the remainder of the URL contains a "/". 
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
        #If the domain does not have at least two parts, meaning there is no main domain, it can be set to an empty string or handle it as needed. 
        #example: localhost or IP address.
        main_domain = ""
        tld = ""

    #extract subdomains (all parts except the last two).
    subdomains = domain_parts[:-2]

    #store extracted components in a dictionary for easy access.
    result = {"protocol": protocol,"domain": domain,"main_domain": main_domain,
        "tld": tld,"subdomains": subdomains,"path": path,"query": query}

    return result