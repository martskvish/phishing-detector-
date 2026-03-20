import sqlite3


def decompose_url(url):

    #initializes variables to store different components of the URL.
    protocol = ""
    domain = ""
    path = ""
    query = ""

    #Check if the URL contains "://"
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

''''
def SQL_URL_database_extraction():
   
    #Connects to a SQLite database named sus_keywords.db and creates a cursor object to interact with the database.
    connection = sqlite3.connect("DB/sus_keywords.db")
    cursor = connection.cursor() 

    cursor.execute("SELECT keyword, severity, weight FROM url_suspicious_characters")
    url_phrases = cursor.fetchall()

    #Close the database connection to free up resources and keep data safe.
    connection.close()
    return url_phrases

'''
def levenshteins_distance_domain(domain):
    
    len_domain = len(domain)  
    
    #initializes variables
    lowest_distnace = float('inf')
    closest_domain = ""

    #Connect to a SQLite database names cert_domain.db and use cursor to interact with DB.
    connection = sqlite3.connect("DB/cert_domain.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM domains")


    for row in cursor.fetchall():
        len_cert_domain = len(row[1])
        
        #Create 2D array with first colume and row representing characters from each string
        array = [[0] * (len_domain + 1) for _ in range(len_cert_domain + 1)]

        #In first column insert numbers one growing by 1 representing each character 
        for i in range(len_cert_domain +1):
                array[i][0] = i

        #In first row insert numbers one growing by 1 representing each character
        for j in range(len_domain + 1):
                array[0][j] = j


        #Loop through every value in the 2D array, skip the borders which are alreday filled.
        #If same indexed characters from both strings are same copy previous value.
        #Else get lowest value from top, top left and left neighbours and plus 1.
        for i in range(1, len_cert_domain + 1):
            for j in range(1, len_domain + 1):
                        if domain[j-1] == row[1][i-1]:
                            array[i][j]= array[i-1][j-1]
                        else:
                            array[i][j] = min(array[i-1][j-1], array[i-1][j], array[i][j-1]) + 1

        #Distnace between domain being analysed and certified domain.
        distance = array[len_cert_domain][len_domain]

        #Store lowest dsitance and closes domain to original domain.
        if distance < lowest_distnace:
            lowest_distnace = distance
            closest_domain = row[1]

    #Close connection and return distance and closest domain.
    connection.close()
    return closest_domain, lowest_distnace
            
def analyse_subdomain_path(subdomain, path):
     
    
    #Connect to a SQLite database names sus_keyword.db and use cursor objects to interact with each table.
    connection = sqlite3.connect("DB/sus_keywords.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM url_subdomain_keywords")
    subdomain_rows = cursor.fetchall()
    cursor.execute("SELECT * FROM url_suspicious_characters") 
    character_rows = cursor.fetchall()
    cursor.execute("SELECT * FROM url_path_keywords")
    path_rows = cursor.fetchall()

    #Initializes empty variables
    detected_subdomains = []
    detected_chars = []
    detected_words_path = []
    total_score = 0 

    #MAYBE IMPLEMENT levenshteins_distance_sub_domain.
    #Check if subdomain contains suspicious words.
    #
    subdomain_str = ''.join(subdomain)
    for row in subdomain_rows:
        sus_domain = row[1]
        severity = row[2]
        weight = row[3]


        if sus_domain in subdomain_str.lower():
            total_score = total_score + weight
            detected_subdomains.append((sus_domain, severity, weight))


    #Check if URL's path contains suspicious characters.
    for row in character_rows:
        char = row[1]
        severity = row[2]
        weight = row[3]

        if char in path:
            total_score = total_score + weight
            detected_chars.append((char, severity, weight))
    
    #Check if URL's path contains suspicious words.
    for row in path_rows:
        word = row[1]
        severity = row[2]
        weight = row[3]

        if word in path.lower():
            total_score = total_score + weight
            detected_words_path.append((char, severity, weight))

    #Close connection and return detected elements
    connection.close()
    return detected_subdomains, detected_chars, detected_words_path, total_score
             